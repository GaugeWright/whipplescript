//! The custodian daemon's listener: newline-delimited JSON over a Unix
//! domain socket, thread per connection — the repo's execution model
//! (threads, not async), and the transport that makes principal separation
//! real: the custodian runs as its own user and whip talks to it only
//! through this socket.
//!
//! Each request line is one [`CustodyCall`]; each reply line is one
//! [`CustodyReply`]. A line that does not parse — including any operation
//! outside the closed vocabulary, `get` first among them — gets a protocol
//! error object and closes the connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use whipplescript_custody::{CustodyCall, CUSTODY_PROTOCOL};

use crate::Custodian;

/// Per-line request cap: custody calls are small; a multi-megabyte line is a
/// caller bug or an attack, not a request.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

pub fn serve(custodian: Arc<Custodian>, socket_path: &Path) -> std::io::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    // Owner-only: the socket is the authority boundary's front door.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let custodian = Arc::clone(&custodian);
        std::thread::spawn(move || {
            let _ = handle_connection(&custodian, stream);
        });
    }
    Ok(())
}

fn handle_connection(custodian: &Custodian, stream: UnixStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_LINE_BYTES as u64);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        reader.set_limit(MAX_LINE_BYTES as u64);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_call(trimmed) {
            Ok(call) => {
                let reply = custodian.handle(&call);
                write_line(
                    &mut writer,
                    &serde_json::to_value(&reply).unwrap_or_default(),
                )?;
            }
            Err(detail) => {
                write_line(
                    &mut writer,
                    &serde_json::json!({ "protocol_error": detail }),
                )?;
                return Ok(());
            }
        }
    }
}

fn parse_call(line: &str) -> Result<CustodyCall, String> {
    let call: CustodyCall =
        serde_json::from_str(line).map_err(|e| format!("malformed custody call: {e}"))?;
    if call.protocol != CUSTODY_PROTOCOL {
        return Err(format!("unsupported protocol {:?}", call.protocol));
    }
    Ok(call)
}

fn write_line(w: &mut impl Write, value: &serde_json::Value) -> std::io::Result<()> {
    let mut body = serde_json::to_string(value).unwrap_or_default();
    body.push('\n');
    w.write_all(body.as_bytes())
}

/// Client half, re-exported from the protocol crate: whip's transport to a
/// custodian daemon on this box. It lives with the protocol so callers do
/// not need the daemon crate to speak to a daemon.
pub use whipplescript_custody::client::UnixSocketTransport;
