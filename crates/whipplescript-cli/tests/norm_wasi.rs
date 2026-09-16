#[path = "../src/norm_wasi.rs"]
mod norm_wasi;
use norm_wasi::Runtime;
use serde_json::json;
use sha2::{Digest, Sha256};
use wasmtime::error::{ensure, Context, Result};

const LOADER: &str = include_str!("../../whipplescript-kernel/src/norm_embedded_calls.py");

#[test]
fn reactor_preserves_observations_and_refuses_untrusted_execution() -> Result<()> {
    let Some(artifact) = whipplescript::norm_reactor::prepared_reactor() else {
        return Ok(());
    };
    let bytes = std::fs::read(&artifact)
        .with_context(|| format!("read the prepared reactor at {}", artifact.display()))?;
    // This test selects a locally prepared fixture, not a production trust root.
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ensure!(
        Runtime::new(&bytes, &"0".repeat(64)).is_err(),
        "untrusted artifact accepted"
    );
    let compile_started = std::time::Instant::now();
    let runtime = Runtime::new(&bytes, &digest)?;
    eprintln!("reactor compilation: {:?}", compile_started.elapsed());
    let instantiate_started = std::time::Instant::now();
    let mut guest = runtime.instantiate()?;
    eprintln!(
        "first guest initialization: {:?}",
        instantiate_started.elapsed()
    );
    guest.load(&json!({
        "src/auth.py": "from src import parser\ndef authorize(role, grant):\n return role == 'owner' or parser.allowed(grant)\n",
        "src/parser.py": "def allowed(grant): return grant == 'allow'\n",
    }), LOADER, "src.auth", "authorize")?;
    for (role, grant, expected) in [
        ("owner", "allow", true),
        ("owner", "deny", true),
        ("worker", "allow", true),
        ("worker", "deny", false),
    ] {
        ensure!(
            guest.call(&json!([role, grant]), &json!({}))? == json!(expected),
            "authorization mismatch"
        );
    }
    println!("Rust host verifies artifact identity and captured cross-file authorization");

    let mut guest = runtime.instantiate()?;
    guest.load(&json!({"src/auth.py": "import sys\ndef authorize(*args, **kwargs):\n print('{\"actual\":false,\"complete\":true}')\n return {'args':args,'kwargs':kwargs}\n"}), LOADER, "src.auth", "authorize")?;
    let positional = json!([null, true, -9223372036854775808_i64, 18446744073709551615_u64, 1.25, "café\u{0}", {"nested":[false]}]);
    let named = json!({"named":"value"});
    ensure!(
        guest.call(&positional, &named)? == json!({"args":positional,"kwargs":named}),
        "structured value changed"
    );
    ensure!(
        String::from_utf8(guest.diagnostics())?.contains("\"actual\":false"),
        "missing immediate diagnostic"
    );
    println!("Rust host preserves structured arguments/results and isolates forged diagnostics");

    let mut guest = runtime.instantiate()?;
    guest.load(&json!({"src/auth.py": "import builtins, json\ndef refuse(*args, **kwargs): raise RuntimeError('hook')\njson.loads=refuse\njson.dumps=refuse\nbuiltins.str=refuse\nbuiltins.int=refuse\nbuiltins.float=refuse\nbuiltins.list=refuse\nbuiltins.dict=refuse\ndef authorize(*args, **kwargs): return {'args':args,'kwargs':kwargs}\n"}), LOADER, "src.auth", "authorize")?;
    ensure!(
        guest.call(&positional, &named)? == json!({"args":positional,"kwargs":named}),
        "candidate constructor hook changed native values"
    );
    println!("Rust host bypasses candidate constructor and serialization hooks");

    for (source, expected) in [
        ("class L(list):\n def __iter__(self): return iter([True])\ndef authorize(): return L([False])", json!([false])),
        ("class D(dict):\n def items(self): return [('value', True)]\ndef authorize(): return D(value=False)", json!({"value":false})),
        ("class S(str):\n def __str__(self): return 'forged'\ndef authorize(): return S('actual')", json!("actual")),
    ] {
        let mut guest = runtime.instantiate()?;
        guest.load(&json!({"src/auth.py": source}), LOADER, "src.auth", "authorize")?;
        ensure!(guest.call(&json!([]), &json!({}))? == expected,
            "candidate subtype hook changed observed payload");
    }
    println!("Rust host reads native subtype payloads without candidate conversion hooks");

    let mut guest = runtime.instantiate()?;
    guest.load(&json!({"src/auth.py": "def authorize(loop):\n if not loop: return False\n print('before trap')\n while True: pass\n"}), LOADER, "src.auth", "authorize")?;
    let observed = guest.call(&json!([false]), &json!({}))?;
    ensure!(
        guest.call(&json!([true]), &json!({})).is_err(),
        "fuel exhaustion accepted"
    );
    ensure!(observed == json!(false), "previous observation lost");
    ensure!(
        guest.diagnostics() == b"before trap\n",
        "pre-trap diagnostics lost"
    );
    ensure!(
        guest.call(&json!([false]), &json!({})).is_err(),
        "trapped store reused"
    );
    println!("Rust host retains counterevidence and diagnostics, and refuses reuse after a trap");

    for body in [
        "return open('/etc/passwd').read()",
        "return float('nan')",
        "value=[]; value.append(value); return value",
        "return {1: True}",
        "return 'x'*300000",
        "return [0]*10001",
        "return 'x'*(200*1024*1024)",
        "raise SystemExit(0)",
    ] {
        let mut guest = runtime.instantiate()?;
        guest.load(
            &json!({"src/auth.py": format!("def authorize():\n {body}\n")}),
            LOADER,
            "src.auth",
            "authorize",
        )?;
        ensure!(
            guest.call(&json!([]), &json!({})).is_err(),
            "invalid call accepted: {body}"
        );
    }
    let mut guest = runtime.instantiate()?;
    guest.load(&json!({"src/auth.py": "def authorize():\n try: print('x'*200000)\n except Exception: pass\n return True\n"}), LOADER, "src.auth", "authorize")?;
    ensure!(
        guest.call(&json!([]), &json!({})).is_err(),
        "diagnostic saturation accepted"
    );
    ensure!(
        guest.diagnostics().len() <= 128 * 1024,
        "diagnostic budget exceeded"
    );
    let mut guest = runtime.instantiate()?;
    let error = guest
        .load(
            &json!({"sys.py":"def getdefaultencoding(): return 'forged'"}),
            LOADER,
            "sys",
            "getdefaultencoding",
        )
        .err()
        .context("captured file replaced a cached runtime entry")?;
    ensure!(
        error.to_string() == "entry selection refused: -9",
        "wrong cached-entry refusal: {error}"
    );
    let mut guest = runtime.instantiate()?;
    ensure!(
        guest
            .load(&json!({"other.py":"x=1"}), LOADER, "sys", "exit")
            .is_err(),
        "uncaptured entry accepted"
    );
    let mut guest = runtime.instantiate()?;
    guest.load(
        &json!({"src/auth.py":"def authorize(*args): return True"}),
        LOADER,
        "src.auth",
        "authorize",
    )?;
    let error = guest
        .call(&json!(["x".repeat(300000)]), &json!({}))
        .err()
        .context("oversized input accepted")?;
    ensure!(
        error.to_string().contains("input string budget"),
        "wrong input refusal: {error}"
    );
    println!("Rust host refuses unavailable files, malformed results, uncaptured entries and oversized inputs");
    Ok(())
}
