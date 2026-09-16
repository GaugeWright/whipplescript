//! Host-owned calls into a content-pinned CPython WASI reactor.
use serde_json::Value;
use sha2::{Digest, Sha256};
use wasmtime::error::{bail, ensure, Context, Result};
use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};
use wasmtime_wasi::{p1::WasiP1Ctx, p2::pipe::MemoryOutputPipe, WasiCtxBuilder};

struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

pub struct Runtime {
    engine: Engine,
    module: Module,
}
impl Runtime {
    /// The caller supplies an independently trusted digest; an adjacent manifest
    /// is not authority to select executable code.
    pub fn new(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        Self::with_optimization(bytes, expected_sha256, wasmtime::OptLevel::None)
    }
    pub fn with_optimization(
        bytes: &[u8],
        expected_sha256: &str,
        optimization: wasmtime::OptLevel,
    ) -> Result<Self> {
        ensure!(
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                == expected_sha256,
            "runtime artifact digest mismatch"
        );
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .max_wasm_stack(1024 * 1024)
            .cranelift_opt_level(optimization);
        let engine = Engine::new(&config)?;
        let module = Module::new(&engine, bytes)?;
        Ok(Self { engine, module })
    }
    pub fn instantiate(&self) -> Result<Guest> {
        let diagnostics = MemoryOutputPipe::new(128 * 1024);
        let wasi = WasiCtxBuilder::new()
            .args(&["/norm-observer"])
            .stdout(diagnostics.clone())
            .stderr(diagnostics.clone())
            .build_p1();
        // No inherited environment, arguments, stdin, sockets or directory preopens.
        let mut store = Store::new(
            &self.engine,
            State {
                wasi,
                limits: StoreLimitsBuilder::new()
                    .memory_size(128 * 1024 * 1024)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(500_000_000)?;
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state: &mut State| &mut state.wasi)?;
        let instance = linker.instantiate(&mut store, &self.module)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("missing guest memory")?;
        instance
            .get_typed_func::<(), ()>(&mut store, "_initialize")?
            .call(&mut store, ())?;
        let version = instance
            .get_typed_func::<(), u32>(&mut store, "norm_python_version")?
            .call(&mut store, ())?;
        ensure!(
            version == 0x030e07f0,
            "reactor was not compiled with CPython 3.14.7 final"
        );
        let status = instance
            .get_typed_func::<(), i32>(&mut store, "norm_init")?
            .call(&mut store, ())?;
        ensure!(status == 0, "guest initialization refused: {status}");
        Ok(Guest {
            store,
            instance,
            memory,
            diagnostics,
            usable: true,
        })
    }
}

pub struct Guest {
    store: Store<State>,
    instance: Instance,
    memory: Memory,
    diagnostics: MemoryOutputPipe,
    usable: bool,
}
impl Guest {
    fn text(&mut self, value: &str) -> Result<u32> {
        let size = u32::try_from(value.len().checked_add(1).context("input size overflow")?)?;
        let pointer = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "malloc")?
            .call(&mut self.store, size)?;
        ensure!(pointer != 0, "guest allocation failed");
        self.memory
            .write(&mut self.store, pointer as usize, value.as_bytes())?;
        self.memory
            .write(&mut self.store, pointer as usize + value.len(), &[0])?;
        Ok(pointer)
    }
    fn free(&mut self, pointer: u32) -> Result<()> {
        self.instance
            .get_typed_func::<u32, ()>(&mut self.store, "free")?
            .call(&mut self.store, pointer)?;
        Ok(())
    }
    fn drop_value(&mut self, value: u32) -> Result<()> {
        self.instance
            .get_typed_func::<u32, ()>(&mut self.store, "norm_drop")?
            .call(&mut self.store, value)?;
        Ok(())
    }
    fn construct(
        &mut self,
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
    ) -> Result<u32> {
        ensure!(
            depth <= 32 && *nodes > 0,
            "input depth or node budget exceeded"
        );
        *nodes -= 1;
        let handle = match value {
            Value::Null => self
                .instance
                .get_typed_func::<(), u32>(&mut self.store, "norm_new_none")?
                .call(&mut self.store, ())?,
            Value::Bool(value) => self
                .instance
                .get_typed_func::<i32, u32>(&mut self.store, "norm_new_bool")?
                .call(&mut self.store, i32::from(*value))?,
            Value::Number(value) if value.is_f64() => self
                .instance
                .get_typed_func::<f64, u32>(&mut self.store, "norm_new_float")?
                .call(&mut self.store, value.as_f64().context("invalid float")?)?,
            Value::Number(value) => {
                let pointer = self.text(&value.to_string())?;
                let handle = self
                    .instance
                    .get_typed_func::<u32, u32>(&mut self.store, "norm_new_integer")?
                    .call(&mut self.store, pointer)?;
                self.free(pointer)?;
                handle
            }
            Value::String(value) => {
                *bytes = bytes
                    .checked_sub(value.len())
                    .context("input string budget exceeded")?;
                let pointer = self.text(value)?;
                let handle = self
                    .instance
                    .get_typed_func::<(u32, u32), u32>(&mut self.store, "norm_new_string")?
                    .call(&mut self.store, (pointer, u32::try_from(value.len())?))?;
                self.free(pointer)?;
                handle
            }
            Value::Array(values) => {
                ensure!(values.len() <= *nodes, "input node budget exceeded");
                let handle = self
                    .instance
                    .get_typed_func::<(), u32>(&mut self.store, "norm_new_list")?
                    .call(&mut self.store, ())?;
                for value in values {
                    let child = self.construct(value, depth + 1, nodes, bytes)?;
                    let status = self
                        .instance
                        .get_typed_func::<(u32, u32), i32>(&mut self.store, "norm_list_push")?
                        .call(&mut self.store, (handle, child))?;
                    self.drop_value(child)?;
                    ensure!(status == 0, "guest list construction refused");
                }
                handle
            }
            Value::Object(values) => {
                ensure!(values.len() <= *nodes / 2, "input node budget exceeded");
                let handle = self
                    .instance
                    .get_typed_func::<(), u32>(&mut self.store, "norm_new_dict")?
                    .call(&mut self.store, ())?;
                for (key, value) in values {
                    let key =
                        self.construct(&Value::String(key.clone()), depth + 1, nodes, bytes)?;
                    let value = self.construct(value, depth + 1, nodes, bytes)?;
                    let status = self
                        .instance
                        .get_typed_func::<(u32, u32, u32), i32>(&mut self.store, "norm_dict_set")?
                        .call(&mut self.store, (handle, key, value))?;
                    self.drop_value(key)?;
                    self.drop_value(value)?;
                    ensure!(status == 0, "guest map construction refused");
                }
                handle
            }
        };
        ensure!(handle != 0, "guest value construction failed");
        Ok(handle)
    }
    /// Captured files have a separate budget from invocation values.
    pub fn load(
        &mut self,
        files: &Value,
        loader: &str,
        module: &str,
        function: &str,
    ) -> Result<()> {
        ensure!(self.usable, "guest was terminated");
        self.usable = false;
        ensure!(
            !module.contains('\0') && !function.contains('\0'),
            "entry contains NUL"
        );
        let map = files.as_object().context("capture must be a file map")?;
        let path = module.replace('.', "/");
        let choices = [format!("{path}.py"), format!("{path}/__init__.py")];
        ensure!(
            choices
                .iter()
                .filter(|path| map.contains_key(*path))
                .count()
                == 1,
            "entry not uniquely captured"
        );
        ensure!(
            map.values().all(Value::is_string),
            "capture contents must be strings"
        );
        let files = self.construct(files, 0, &mut 10000, &mut (2 * 1024 * 1024))?;
        let loader = self.text(loader)?;
        let status = self
            .instance
            .get_typed_func::<(u32, u32), i32>(&mut self.store, "norm_install_files")?
            .call(&mut self.store, (files, loader))?;
        self.drop_value(files)?;
        self.free(loader)?;
        ensure!(status == 0, "loader refused: {status}");
        let module = self.text(module)?;
        let function = self.text(function)?;
        let status = self
            .instance
            .get_typed_func::<(u32, u32), i32>(&mut self.store, "norm_select")?
            .call(&mut self.store, (module, function))?;
        self.free(module)?;
        self.free(function)?;
        ensure!(status == 0, "entry selection refused: {status}");
        ensure!(
            self.diagnostics.contents().len() < 128 * 1024,
            "candidate diagnostics reached the capture limit"
        );
        self.usable = true;
        Ok(())
    }
    pub fn call(&mut self, args: &Value, kwargs: &Value) -> Result<Value> {
        ensure!(self.usable, "guest was terminated");
        self.usable = false;
        ensure!(
            args.is_array() && kwargs.is_object(),
            "invalid argument containers"
        );
        self.store.set_fuel(20_000_000)?;
        let mut nodes = 10000;
        let mut bytes = 256 * 1024;
        let args = self.construct(args, 0, &mut nodes, &mut bytes)?;
        let kwargs = self.construct(kwargs, 0, &mut nodes, &mut bytes)?;
        let status = self
            .instance
            .get_typed_func::<(u32, u32), i32>(&mut self.store, "norm_call_values")?
            .call(&mut self.store, (args, kwargs))?;
        if status != 0 {
            bail!("candidate invocation refused: {status}");
        }
        let pointer = self
            .instance
            .get_typed_func::<(), u32>(&mut self.store, "norm_result_ptr")?
            .call(&mut self.store, ())?;
        let size = self
            .instance
            .get_typed_func::<(), u32>(&mut self.store, "norm_result_len")?
            .call(&mut self.store, ())?;
        ensure!(size <= 2 * 1024 * 1024, "result byte budget exceeded");
        let mut bytes = vec![0; size as usize];
        self.memory
            .read(&self.store, pointer as usize, &mut bytes)?;
        let value = serde_json::from_slice(&bytes)?;
        self.drop_value(args)?;
        self.drop_value(kwargs)?;
        ensure!(
            self.diagnostics.contents().len() < 128 * 1024,
            "candidate diagnostics reached the capture limit"
        );
        self.usable = true;
        Ok(value)
    }
    pub fn diagnostics(&self) -> Vec<u8> {
        self.diagnostics.contents().to_vec()
    }
}
