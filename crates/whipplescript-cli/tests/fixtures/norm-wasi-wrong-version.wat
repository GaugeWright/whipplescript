;; A digest-verified reactor must still match the declared Python ABI/version.
;; Initialization traps if the host incorrectly proceeds past the version check.
(module
  (memory (export "memory") 1)
  (func (export "_initialize"))
  (func (export "norm_python_version") (result i32) i32.const 0x030e08f0)
  (func (export "norm_init") (result i32) unreachable)
)
