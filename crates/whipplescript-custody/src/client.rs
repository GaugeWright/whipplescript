//! whip's client transport to a custodian daemon on this box: one
//! newline-delimited JSON call per connection over a Unix domain socket
//! (the server half lives in `whipplescript-custodian::serve`). Unix-only,
//! so the protocol crate stays wasm-clean; a wasm host supplies its own
//! [`CustodyTransport`].

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::{CustodyCall, CustodyReply, CustodyTransport, TransportError};

/// Matches the daemon's per-line cap.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// The conventional environment variable naming the custodian socket.
pub const CUSTODIAN_SOCKET_ENV: &str = "WHIPPLESCRIPT_CUSTODIAN_SOCKET";

pub struct UnixSocketTransport {
    socket_path: PathBuf,
}

impl UnixSocketTransport {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// The transport named by `WHIPPLESCRIPT_CUSTODIAN_SOCKET`, if set.
    pub fn from_env() -> Option<Self> {
        std::env::var_os(CUSTODIAN_SOCKET_ENV).map(|path| Self::new(PathBuf::from(path)))
    }
}

impl CustodyTransport for UnixSocketTransport {
    fn call(&self, call: CustodyCall) -> Result<CustodyReply, TransportError> {
        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
        let mut writer = stream
            .try_clone()
            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
        let wire = serde_json::to_string(&call)
            .map_err(|e| TransportError::Protocol(format!("unserializable call: {e}")))?;
        writer
            .write_all(wire.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
        let mut reader = BufReader::new(stream).take(MAX_LINE_BYTES as u64);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
        let value: serde_json::Value = serde_json::from_str(line.trim())
            .map_err(|e| TransportError::Protocol(format!("malformed reply: {e}")))?;
        if let Some(detail) = value.get("protocol_error").and_then(|v| v.as_str()) {
            return Err(TransportError::Protocol(detail.to_string()));
        }
        serde_json::from_value(value)
            .map_err(|e| TransportError::Protocol(format!("malformed reply: {e}")))
    }
}
