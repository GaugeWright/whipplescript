//! Host-owned native payload protection. The owner supplies key custody and
//! authenticated encryption; the store supplies exact associated coordinates.
use std::sync::Arc;

use crate::{StoreError, StoreResult};

/// An embedding host's content authority. Implementations must authenticate
/// `associated_data`, refuse unavailable keys, and never return plaintext as a
/// sealing fallback. No key material is persisted by WhippleScript.
pub trait PayloadCodec: Send + Sync {
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>>;
    fn open(&self, associated_data: &[u8], ciphertext: &[u8]) -> StoreResult<Vec<u8>>;

    /// Exclude key erasure while `publish` verifies and publishes retained
    /// references. Call it once, or refuse without calling it. Reads made inside
    /// the callback must remain possible even while another thread wants erasure.
    fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct PayloadProtection {
    domain: String,
    codec: Arc<dyn PayloadCodec>,
}

impl PayloadProtection {
    pub fn new(domain: impl Into<String>, codec: Arc<dyn PayloadCodec>) -> StoreResult<Self> {
        let domain = domain.into();
        if domain.trim().is_empty() {
            return Err(StoreError::fault(
                "payload protection",
                "empty protection domain",
            ));
        }
        Ok(Self { domain, codec })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    fn associated_data(&self, plane: &str, coordinate: &str) -> StoreResult<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "whipplescript.native-payload.v1",
            &self.domain,
            plane,
            coordinate,
        ))?)
    }

    pub(crate) fn seal(
        &self,
        plane: &str,
        coordinate: &str,
        plaintext: &[u8],
    ) -> StoreResult<Vec<u8>> {
        self.codec
            .seal(&self.associated_data(plane, coordinate)?, plaintext)
    }

    pub(crate) fn open(
        &self,
        plane: &str,
        coordinate: &str,
        ciphertext: &[u8],
    ) -> StoreResult<Vec<u8>> {
        self.codec
            .open(&self.associated_data(plane, coordinate)?, ciphertext)
    }

    pub(crate) fn retain<T>(&self, publish: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
        let mut publish = Some(publish);
        let mut result = None;
        let mut calls = 0;
        self.codec.retain(&mut || {
            calls += 1;
            let callback = publish.take().ok_or_else(|| {
                StoreError::fault("payload protection", "codec repeated retained publication")
            })?;
            result = Some(callback()?);
            Ok(())
        })?;
        if calls != 1 {
            return Err(StoreError::fault(
                "payload protection",
                "codec changed publication cardinality",
            ));
        }
        result.ok_or_else(|| {
            StoreError::fault("payload protection", "codec omitted retained publication")
        })
    }
}

/// SQL helpers let owner transaction helpers use the same codec as object
/// methods without passing key custody through every pure tracker operation.
pub(crate) fn register_sql_functions(
    connection: &rusqlite::Connection,
    protection: Option<PayloadProtection>,
) -> StoreResult<()> {
    use rusqlite::{functions::FunctionFlags, types::Value};
    for (name, seal) in [("whip_payload_seal", true), ("whip_payload_open", false)] {
        let protection = protection.clone();
        connection.create_scalar_function(
            name,
            3,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY,
            move |context| {
                let value: Value = context.get(2)?;
                let Some(protection) = &protection else {
                    return Ok(value);
                };
                let bytes = match value {
                    Value::Null => return Ok(Value::Null),
                    Value::Text(text) => text.into_bytes(),
                    Value::Blob(bytes) => bytes,
                    _ => {
                        return Err(rusqlite::Error::UserFunctionError(Box::new(
                            std::io::Error::other(
                                "native payload: invalid SQL payload representation",
                            ),
                        )))
                    }
                };
                let plane: String = context.get(0)?;
                let coordinate: String = context.get(1)?;
                let transformed = if seal {
                    protection.seal(&plane, &coordinate, &bytes)
                } else {
                    protection.open(&plane, &coordinate, &bytes)
                }
                .map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
                        "{error:?}"
                    ))))
                })?;
                if seal {
                    Ok(Value::Blob(transformed))
                } else {
                    String::from_utf8(transformed)
                        .map(Value::Text)
                        .map_err(|error| {
                            rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(
                                format!("{error:?}"),
                            )))
                        })
                }
            },
        )?;
    }
    Ok(())
}
