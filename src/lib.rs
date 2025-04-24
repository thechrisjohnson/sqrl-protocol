//! Code needed for SQRL client and server communication

#![deny(missing_docs)]
pub mod client_request;
pub mod error;
pub mod server_response;

use crate::error::SqrlError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{collections::HashMap, fmt, result};
use url::Url;

/// The general protocol for SQRL urls
pub const SQRL_PROTOCOL: &str = "sqrl";

/// The current list of supported versions
pub const PROTOCOL_VERSIONS: &str = "1";

/// A default result type for the crate
pub type Result<G> = result::Result<G, SqrlError>;

/// Parses a SQRL url and breaks it into its parts
#[derive(Debug, PartialEq)]
pub struct SqrlUrl {
    url: Url,
}

impl SqrlUrl {
    /// Parse a SQRL url string and convert it into the object
    /// ```rust
    /// use sqrl_protocol::SqrlUrl;
    ///
    /// let sqrl_url = SqrlUrl::parse("sqrl://example.com?nut=1234abcd").unwrap();
    /// ```
    pub fn parse(url: &str) -> Result<Self> {
        let parsed = Url::parse(url)?;
        if parsed.scheme() != SQRL_PROTOCOL {
            return Err(SqrlError::new(format!(
                "Invalid sqrl url, incorrect protocol: {}",
                url
            )));
        }
        if parsed.domain().is_none() {
            return Err(SqrlError::new(format!(
                "Invalid sqrl url, missing domain: {}",
                url
            )));
        }

        Ok(SqrlUrl { url: parsed })
    }

    /// Get the auth domain used for calculating identities
    /// ```rust
    /// use sqrl_protocol::SqrlUrl;
    ///
    /// let sqrl_url = SqrlUrl::parse("sqrl://example.com/auth/path?nut=1234abcd").unwrap();
    /// assert_eq!("example.com/auth/path", sqrl_url.get_auth_domain())
    /// ```
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
) -> Result<String> {
    match map.get(key) {
        Some(x) => Ok(x.to_owned()),
        None => Err(SqrlError::new(error_message.to_owned())),
    }
}

pub(crate) fn parse_query_data(query: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::<String, String>::new();
    for token in query.split('&') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        } else {
            return Err(SqrlError::new("Invalid query data".to_owned()));
        }
    }
    Ok(map)
}

pub(crate) fn decode_public_key(key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_32(&x)?,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded public key {}",
                key
            )))
        }
    }

    match VerifyingKey::from_bytes(&bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(SqrlError::new(format!(
            "Failed to generate public key from {}: {}",
            key, e
        ))),
    }
}

pub(crate) fn decode_signature(key: &str) -> Result<Signature> {
    let bytes: [u8; 64];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_64(&x)?,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded signature {}",
                key
            )))
        }
    }

    Ok(Signature::from_bytes(&bytes))
}

pub(crate) fn parse_newline_data(data: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::<String, String>::new();
    for token in data.split('\n') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.trim().to_owned());
        } else if !token.is_empty() {
            return Err(SqrlError::new(format!("Invalid newline data {}", token)));
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

pub(crate) fn vec_to_u8_32(vector: &[u8]) -> Result<[u8; 32]> {
    let mut result = [0; 32];
    if vector.len() != 32 {
        return Err(SqrlError::new(format!(
            "Error converting vec<u8> to [u8; 32]: Expected 32 bytes, but found {}",
            vector.len()
        )));
    }

    result[..32].copy_from_slice(&vector[..32]);
    Ok(result)
}

pub(crate) fn vec_to_u8_64(vector: &[u8]) -> Result<[u8; 64]> {
    let mut result = [0; 64];
    if vector.len() != 64 {
        return Err(SqrlError::new(format!(
            "Error converting vec<u8> to [u8; 64]: Expected 64 bytes, but found {}",
            vector.len()
        )));
    }

    result[..64].copy_from_slice(&vector[..64]);
    Ok(result)
}

/// The versions of the sqrl protocol supported by a client/server
#[derive(Debug, PartialEq)]
pub struct ProtocolVersion {
    versions: u128,
    max_version: u8,
}

impl ProtocolVersion {
    /// Create a new object based on the version string
    /// ```rust
    /// use sqrl_protocol::ProtocolVersion;
    ///
    /// let version = ProtocolVersion::new("1,3,6-10").unwrap();
    /// ```
    pub fn new(versions: &str) -> Result<Self> {
        let mut prot = ProtocolVersion {
            versions: 0,
            max_version: 0,
        };
        for sub in versions.split(',') {
            if sub.contains('-') {
                let mut versions = sub.split('-');

                // Parse out the lower and higher end of the range
                let low: u8 = match versions.next() {
                    Some(x) => x.parse::<u8>()?,
                    None => {
                        return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                    }
                };
                let high: u8 = match versions.next() {
                    Some(x) => x.parse::<u8>()?,
                    None => {
                        return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                    }
                };

                // Make sure the range is valid
                if low >= high {
                    return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                }

                // Set the necessary values
                for i in low..high + 1 {
                    prot.versions |= 0b00000001 << (i - 1);
                }
                if high > prot.max_version {
                    prot.max_version = high;
                }
            } else {
                let version = sub.parse::<u8>()?;
                prot.versions |= 0b00000001 << (version - 1);
                if version > prot.max_version {
                    prot.max_version = version;
                }
            }
        }

        Ok(prot)
    }

    /// Compares two protocol version objects, returning the highest version
    /// supported by both
    /// ```rust
    /// use sqrl_protocol::ProtocolVersion;
    ///
    /// let version = ProtocolVersion::new("1,3,5,7,9").unwrap();
    /// let version2 = ProtocolVersion::new("2,4,5,8,10").unwrap();
    /// assert_eq!(5, version.get_max_matching_version(&version2).unwrap());
    /// ```
    pub fn get_max_matching_version(&self, other: &ProtocolVersion) -> Result<u8> {
        let min_max = if self.max_version > other.max_version {
            other.max_version
        } else {
            self.max_version
        };

        let matches = self.versions & other.versions;

        // Start from the highest match and work our way back
        let bit: u128 = 0b00000001 << min_max;
        for i in 0..min_max {
            if matches & (bit >> i) == bit >> i {
                return Ok(min_max - i + 1);
            }
        }

        Err(SqrlError::new(format!(
            "No matching supported version! Ours: {} Theirs: {}",
            self, other
        )))
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut versions: Vec<String> = Vec::new();
        let mut current_min: Option<u8> = None;
        let mut bit: u128 = 0b00000001;
        for i in 0..self.max_version {
            if self.versions & bit == bit {
                // If we don't have a current min set it.
                // Otherwise, keep going until the range ends
                if current_min.is_none() {
                    current_min = Some(i);
                }
            } else {
                // Did we experience a range, or just a single one?
                if let Some(min) = current_min {
                    if i == min + 1 {
                        // A streak of one
                        versions.push(format!("{}", min + 1));
                    } else {
                        versions.push(format!("{}-{}", min + 1, i));
                    }

                    current_min = None;
                }
            }

            bit <<= 1;
        }

        // If we still have a min set, we need to run that same code again
        if let Some(min) = current_min {
            if self.max_version == min + 1 {
                // A streak of one
                versions.push(format!("{}", min + 1));
            } else {
                versions.push(format!("{}-{}", min + 1, self.max_version));
            }
        }

        write!(f, "{}", versions.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_create_valid_version() {
        ProtocolVersion::new("1,2,6-7").unwrap();
    }

    #[test]
    fn protocol_version_create_invalid_version() {
        if let Ok(version) = ProtocolVersion::new("1,2,7-3") {
            panic!("Version considered valid! {}", version);
        }
    }

    #[test]
    fn protocol_version_match_highest_version() {
        let client = ProtocolVersion::new("1-7").unwrap();
        let server = ProtocolVersion::new("1,3,5").unwrap();
        assert_eq!(5, client.get_max_matching_version(&server).unwrap());
    }

    #[test]
    fn protocol_version_no_version_match() {
        let client = ProtocolVersion::new("1-3,5-7").unwrap();
        let server = ProtocolVersion::new("4,8-12").unwrap();
        if let Ok(x) = client.get_max_matching_version(&server) {
            panic!("Matching version found! {}", x);
        }
    }
}
