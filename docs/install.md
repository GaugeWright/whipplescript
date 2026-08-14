# Install

The WhippleScript CLI is one binary. The name of the binary is `whip`.

These instructions install the most recent published release. If you read these
documents from a local checkout of `main`, the checkout can give a flag or a
JSON field that is newer than that release. To find the exact behavior of a
release, use the documents from the applicable Git tag.

## Prebuilt binaries

Each release publishes an archive, an installer, and a checksum. The releases
cover macOS on Apple Silicon and on Intel, Windows x64, and Linux on x64 and on
ARM64 with GNU libc.

For macOS and Linux, use this command:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-installer.sh | sh
```

For Windows, use this command:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-installer.ps1 | iex"
```

To verify an archive that you downloaded manually, check the archive against its
adjacent `.sha256` file. As an alternative, check the archive against the
`sha256.sum` file of the full release:

```sh
curl -LO https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-x86_64-unknown-linux-gnu.tar.xz
curl -LO https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum --check whipplescript-x86_64-unknown-linux-gnu.tar.xz.sha256
```

On macOS, the `sha256sum` command can be absent. In that condition, use
`shasum -a 256 -c`.

## Homebrew

For macOS and Linux, the tap is available:

```sh
brew tap GaugeWright/tap && brew install whipplescript
```

The release that builds the archives above also publishes the formula, so the
tap serves those same binaries under those same checksums rather than a
separately built copy. Homebrew does not cover Windows; use the PowerShell
installer for that platform.

## From source

This procedure needs a Rust toolchain. Refer to <https://rustup.rs/>.

```sh
git clone https://github.com/GaugeWright/whipplescript.git
cd whipplescript
cargo install --path crates/whipplescript-cli --locked
```

As an alternative, install directly from Git:

```sh
cargo install --git https://github.com/GaugeWright/whipplescript.git --package whipplescript --locked
```

Cargo installs the binary into `~/.cargo/bin`. Make sure that this directory is
on the `PATH`.

## Verify

```sh
whip --version
whip doctor
whip check examples/minimal-noop.whip   # from a checkout
```

The `whip --version` command prints the version of the package. An example is
`whipplescript 0.2.1`. The `whip --help` command also prints the label of the
implementation stage in parentheses. That label is for the tracking of the
project. That label does not replace the version of the package.

The `doctor` command reports the optional tools. The tools are Maude, Apalache,
the Python `jsonschema` package, and the CLI of each provider. You need none of
these tools for development with the fixture. The generated formal checks and
the validation of the report schemas can use the Nix dev shell. Run
`nix develop`. As an alternative, from a checkout, run
`python3 -m pip install -r requirements-dev.txt`.

## Running without installing

From a checkout, use `cargo run -p whipplescript --` in place of `whip` in each
command. Use this method for development on WhippleScript itself.

## Platform notes

- **Gatekeeper on macOS:** the project does not yet sign the prebuilt binaries.
  If macOS blocks a download, install from source. As an alternative, remove the
  quarantine flag, but only after you verify the checksum.
- **libc on Linux:** the binaries use GNU libc. On a system that uses musl,
  install from source. An internal tracker records an artifact for musl.
- **Windows:** the installer updates the `PATH`. Start the terminal again after
  that update.
