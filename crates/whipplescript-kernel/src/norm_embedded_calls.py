"""Pinned captured-source loader for the Rust-owned Python call observer.

Only captured files enter this VM. Invocation identities, expected values,
case accounting and protocol output remain in the embedding, outside frames.
The embedding supplies a bounded diagnostic sink, never the protocol writer.
"""
import sys
import _frozen_importlib

class CapturedLoader:
    def find_spec(self, fullname, path=None, target=None):
        module_path = fullname.replace('.', '/')
        choices = [name for name in (module_path + '.py', module_path + '/__init__.py')
                   if name in captured_files]
        if len(choices) > 1:
            raise ImportError('ambiguous captured module: ' + fullname)
        if choices:
            return _frozen_importlib.ModuleSpec(fullname, self,
                origin=choices[0], is_package=choices[0].endswith('/__init__.py'))
        if any(name.startswith(module_path + '/') for name in captured_files):
            return _frozen_importlib.ModuleSpec(fullname, self, is_package=True)
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        origin = module.__spec__.origin
        if origin is not None:
            module.__file__ = origin
            # This is an importlib Loader: `exec_module` running the source it
            # compiled is what CPython's own SourceLoader does, and is how a
            # module gets imported at all. `origin` can only be a key of
            # `captured_files`, because `find_spec` above chooses it from that
            # dict and returns None otherwise -- so what runs here is the
            # captured program, which is the point of the VM, and nothing else
            # can reach it.
            # nosemgrep: python.lang.security.audit.exec-detected.exec-detected
            exec(compile(captured_files[origin], origin, 'exec'), module.__dict__)

class DiagnosticOutput:
    def write(self, text):
        return capture_diagnostic(text)
    def flush(self):
        pass

sys.stdout = DiagnosticOutput()
sys.__stdout__ = sys.stdout
sys.stderr = DiagnosticOutput()
sys.__stderr__ = sys.stderr
sys.meta_path.insert(0, CapturedLoader())
