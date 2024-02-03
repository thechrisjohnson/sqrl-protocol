//! Code needed for SQRL client and server communication

pub mod client_request;
pub mod error;
pub mod protocol_version;
pub mod server_response;

use crate::error::SqrlProtocolError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use url::Url;
use std::fmt;

/// The general protocl for SQRL urls
pub const SQRL_PROTOCOL: &str = "sqrl";

/// The current list of supported versions
pub const PROTOCOL_VERSIONS: &str = "1";

/// Parses a SQRL url and breaks it into its parts
#[derive(Debug, PartialEq)]
pub struct SqrlUrl {
    url: Url,
}

impl SqrlUrl {
    /// Parse a SQRL url string and convert it into the object
    pub fn parse(url: &str) -> Result<Self, SqrlProtocolError> {
        let parsed = Url::parse(url)?;
        if parsed.scheme() != SQRL_PROTOCOL {
            return Err(SqrlProtocolError::new(format!(
                "Invalid sqrl url, incorrect protocol: {}",
                url
            )));
        }
        if parsed.domain().is_none() {
            return Err(SqrlProtocolError::new(format!(
                "Invalid sqrl url, missing domain: {}",
                url
            )));
        }

        Ok(SqrlUrl { url: parsed })
    }

    /// Get the auth domain used for calculating identities
    pub fn get_auth_domain(&self) -> String {
        format!("{}{}", self.get_domain(), self.get_path())
    }

    fn get_domain(&self) -> String {
        self.url.domain().unwrap().to_lowercase()
    }

    fn get_path(&self) -> String {
        let path = self.url.path().strip_suffix('/').unwrap_or(self.url.path());
        path.to_owned()
    }
}

impl fmt::Display for SqrlUrl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}


pub(crate) fn get_or_error(
    map: &HashMap<String, String>,
    key: &str,
    error_message: &str,
) -> Result<String, SqrlProtocolError> {
    match map.get(key) {
        Some(x) => Ok(x.to_owned()),
        None => Err(SqrlProtocolError::new(error_message.to_owned())),
    }
}

pub(crate) fn parse_query_data(query: &str) -> Result<HashMap<String, String>, SqrlProtocolError> {
    let mut map = HashMap::<String, String>::new();
    for token in query.split('&') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        } else {
            return Err(SqrlProtocolError::new("Invalid query data".to_owned()));
        }
    }
    Ok(map)
}

pub(crate) fn decode_public_key(key: &str) -> Result<VerifyingKey, SqrlProtocolError> {
    let bytes: [u8; 32];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_32(&x)?,
        Err(_) => {
            return Err(SqrlProtocolError::new(format!(
                "Failed to decode base64 encoded public key {}",
                key
            )))
        }
    }

    match VerifyingKey::from_bytes(&bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(SqrlProtocolError::new(format!(
            "Failed to generate public key from {}: {}",
            key, e
        ))),
    }
}

pub(crate) fn decode_signature(key: &str) -> Result<Signature, SqrlProtocolError> {
    let bytes: [u8; 64];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_64(&x)?,
        Err(_) => {
            return Err(SqrlProtocolError::new(format!(
                "Failed to decode base64 encoded signature {}",
                key
            )))
        }
    }

    Ok(Signature::from_bytes(&bytes))
}

pub(crate) fn parse_newline_data(data: &str) -> Result<HashMap<String, String>, SqrlProtocolError> {
    let mut map = HashMap::<String, String>::new();
    for token in data.split('\n') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.trim().to_owned());
        } else if !token.is_empty() {
            return Err(SqrlProtocolError::new(format!("Invalid newline data {}", token)));
        }
    }

    Ok(map)
}

pub(crate) fn encode_newline_data(map: &HashMap<&str, &str>) -> String {
    let mut result = String::new();
    for (key, value) in map.iter() {
        result += &format!("\n{key}={value}");
    }

    result
}

pub(crate) fn vec_to_u8_32(vector: &Vec<u8>) -> Result<[u8; 32], SqrlProtocolError> {
    let mut result = [0; 32];
    if vector.len() != 32 {
        return Err(SqrlProtocolError::new(format!(
            "Error converting vec<u8> to [u8; 32]: Expected 32 bytes, but found {}",
            vector.len()
        )));
    }

    result[..32].copy_from_slice(&vector[..32]);
    Ok(result)
}

pub(crate) fn vec_to_u8_64(vector: &Vec<u8>) -> Result<[u8; 64], SqrlProtocolError> {
    let mut result = [0; 64];
    if vector.len() != 64 {
        return Err(SqrlProtocolError::new(format!(
            "Error converting vec<u8> to [u8; 64]: Expected 64 bytes, but found {}",
            vector.len()
        )));
    }

    result[..64].copy_from_slice(&vector[..64]);
    Ok(result)
}
