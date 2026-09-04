# MTARGET pre-repair receipt fixtures

Generated with the real native store/VCS APIs at WhippleScript source revision
`44302912257d49dbf033fe2543400c640f6fa71b`, the exact source behind GaugeDesk's
published `whipplescript-workstream-host/v1.0.1` pin. These are synthetic test
projects, not copied customer data.

`generate.rs.txt` is the generator used as
`crates/whipplescript-store/examples/mtarget_legacy_receipts.rs` in an isolated
checkout of that revision. Run it with:

```sh
cargo run --locked -p whipplescript-store --example mtarget_legacy_receipts -- target/legacy-receipts
```

The output directory must not exist. The generator closes each SQLite store
before export. Each `.sql` file is the corresponding database's complete
`sqlite3 DATABASE .dump`, including its old schema; each JSON file is the
unchanged serialized output from that runtime. This preserves actual old
storage for upgrade tests without committing SQLite page/free-list artifacts.

Cases:

- `fork`: the parent has moved beyond the chosen cut; an admitted child already
  exists at the old cut, as after losing the original successful fork response.
- `archived`: Main advanced, the receipt was retained, the stream archived, and
  the line lock was released.
- `landed`: Main advanced, but the process stopped before recording the topology
  receipt. The exact pending coordinate and line lock remain.

The tests reopen these schemas through the current owning adapters. Do not
regenerate their expected handles with a newer runtime: the old bytes are the
compatibility evidence. Intentional changes to the fixture must retain its
source revision and generation procedure.
