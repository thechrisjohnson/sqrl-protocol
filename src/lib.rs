//! Code needed for SQRL client and server communication

#![deny(missing_docs)]
pub mod client_request;
pub mod error;
pub mod server_response;

use crate::error::{SqrlError, SqrlUrlError};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{collections::HashMap, fmt, result};
use url::Url;

/// The general protocol for SQRL urls
pub const SQRL_PROTOCOL: &str = "sqrl";

/// The scheme used when posting to SQRL urls (aka "https")
pub const REQUEST_URL_SCHEME: &str = "https";

/// The current list of supported versions
pub const PROTOCOL_VERSIONS: &str = "1";

/// A default result type for the crate
pub type Result<G> = result::Result<G, SqrlError>;

// Used for string replace when dealing with sqrl->https scheme shift
const SQRL_FULL_URL_SCHEME: &str = "sqrl://";
const REQUEST_FULL_URL_SCHEME: &str = "https://";

/// Parses a SQRL url and breaks it into its parts
#[derive(Clone, Debug, PartialEq)]
pub struct SqrlUrl {
    original: String,
    parsed: Url,
    nut: String,
    cancel_url: Option<Url>,
    path_extension: Option<usize>,
    query_parameters: HashMap<String, String>,
}

impl SqrlUrl {
    /// Parse a SQRL url string and convert it into the object
    /// ```rust
    /// use sqrl_protocol::SqrlUrl;
    ///
    /// let sqrl_url = SqrlUrl::parse("sqrl://example.com?nut=1234abcd").unwrap();
    /// ```
    pub fn parse(url: &str) -> std::result::Result<Self, SqrlUrlError> {
        let parsed = match Url::parse(url) {
            Ok(url) => url,
            Err(_) => return Err(SqrlUrlError::InvalidUrl),
        };

        if parsed.scheme() != SQRL_PROTOCOL {
            return Err(SqrlUrlError::UnsupportedScheme);
        }

        let mut query_parameters = HashMap::<String, String>::new();
        for pair in parsed.query_pairs() {
            if query_parameters.contains_key(&*pair.0) {
                return Err(SqrlUrlError::DuplicateParameter((*pair.0).to_string()));
            }

            query_parameters.insert((*pair.0).to_string(), (*pair.1).to_string());
        }

        let nut;
        if let Some(value) = query_parameters.get("nut") {
            nut = value.to_string();
        } else {
            return Err(SqrlUrlError::MissingNut);
        }

        let cancel_url = match query_parameters.get("can") {
            Some(value) => {
                if let Ok(decoded_vec) = BASE64_URL_SAFE_NO_PAD.decode(value) {
                    if let Ok(decoded_value) = String::from_utf8(decoded_vec) {
                        if let Ok(url) = Url::parse(&decoded_value) {
                            Some(url)
                        } else {
                            return Err(SqrlUrlError::InvalidCancelUrl);
                        }
                    } else {
                        return Err(SqrlUrlError::InvalidCancelUrl);
                    }
                } else {
                    return Err(SqrlUrlError::InvalidCancelUrl);
                }
            }
            None => None,
        };

        let path_extension = match query_parameters.get("x") {
            Some(value) => {
                if let Ok(x) = value.parse::<usize>() {
                    Some(x)
                } else {
                    return Err(SqrlUrlError::InvalidPathExtension);
                }
            }
            None => None,
        };

        Ok(SqrlUrl {
            parsed,
            original: url.to_owned(),
            nut,
            cancel_url,
            path_extension,
            query_parameters,
        })
    }

    /// Parses a base64 url-safe value into a SqrlUrl
    pub fn from_base64url(encoded: &str) -> std::result::Result<Self, SqrlUrlError> {
        let decoded_data = match BASE64_URL_SAFE_NO_PAD.decode(encoded) {
            Ok(d) => d,
            Err(_) => return Err(SqrlUrlError::InvalidBase64),
        };

        let data = match String::from_utf8(decoded_data) {
            Ok(d) => d,
            Err(_) => return Err(SqrlUrlError::InvalidUtf8),
        };

        Self::parse(&data)
    }

    /// Gets the original string passed in for parsing
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Gets the host value of this url
    pub fn host(&self) -> &str {
        self.parsed.authority()
    }

    /// Gets the port value of this url
    pub fn port(&self) -> u16 {
        self.parsed.port().unwrap_or(443)
    }

    /// Gets the path value of this url
    pub fn path(&self) -> &str {
        self.parsed.path()
    }

    /// Gets the parsed nut value from the query parameters
    pub fn nut(&self) -> &str {
        &self.nut
    }

    /// Gets the parsed can value from the query parameters
    pub fn cancel_url(&self) -> Option<&Url> {
        self.cancel_url.as_ref()
    }

    /// Gets the parsed x value from the query parameters
    pub fn path_extension(&self) -> Option<usize> {
        self.path_extension
    }

    /// Gets the parsed query parameters
    pub fn query_parameters(&self) -> impl Iterator<Item = (&String, &String)> {
        self.query_parameters.iter()
    }

    /// Get the auth domain used for calculating identities
    /// ```rust
    /// use sqrl_protocol::SqrlUrl;
    ///
    /// let sqrl_url = SqrlUrl::parse("sqrl://example.com/auth/path?nut=1234abcd").unwrap();
    /// assert_eq!("example.com/auth/path", sqrl_url.site_key_string().unwrap())
    /// ```
    pub fn site_key_string(&self) -> std::result::Result<String, SqrlUrlError> {
        let mut path = self.path();
        if let Some(extension) = self.path_extension {
            (path, _) = path.split_at(extension);
        }

        Ok(format!("{}{}", self.host(), path))
    }

    /// Convert a SQRL Url into a URL that can be used for actually querying a server
    /// This just means replacing the sqrl:// scheme with https://
    /// ```rust
    /// use sqrl_protocol::SqrlUrl;
    ///
    /// let sqrl_url = SqrlUrl::parse("sqrl://example.com/auth/path?nut=1234abcd").unwrap();
    /// assert_eq!("https://example.com/auth/path?nut=1234abcd", sqrl_url.get_request_url())
    /// ```
    pub fn get_request_url(&self) -> String {
        self.original
            .replace(SQRL_FULL_URL_SCHEME, REQUEST_FULL_URL_SCHEME)
    }
}

impl fmt::Display for SqrlUrl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.original())
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

    const VALID_SQRL_URL: &str = "sqrl://example.com/auth/path?nut=1234abcd";

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

    #[test]
    fn sqrl_url_parse_accepts_sqrl_url() {
        let url = SqrlUrl::parse(VALID_SQRL_URL);
        assert!(url.is_ok());
    }

    #[test]
    fn sqrl_url_parse_errors_on_invalid_url() {
        let url = SqrlUrl::parse("invalid-url-string");
        assert!(url.is_err());
    }

    #[test]
    fn sqrl_url_authority_for_ip_address() {
        let url = SqrlUrl::parse("sqrl://192.168.1.1/auth/path?nut=1234abcd").unwrap();
        assert_eq!("192.168.1.1", url.host());
    }

    #[test]
    fn sqrl_url_parse_errors_on_incorrect_protocol() {
        let url = SqrlUrl::parse(&VALID_SQRL_URL.replace("sqrl", "https"));
        assert!(url.is_err());
    }

    #[test]
    fn sqrl_url_site_key_string_includes_path() {
        let url = SqrlUrl::parse(VALID_SQRL_URL).unwrap();
        assert_eq!(url.site_key_string().unwrap(), "example.com/auth/path");
    }

    #[test]
    fn sqrl_url_get_site_key_string_no_path_if_not_passed() {
        let url = SqrlUrl::parse("sqrl://example.com?nut=123").unwrap();
        assert_eq!(&url.site_key_string().unwrap(), "example.com");
    }

    #[test]
    fn sqrl_url_get_request_url_returns_https() {
        let sqrl_url = SqrlUrl::parse(VALID_SQRL_URL).unwrap();
        let url = Url::parse(&sqrl_url.get_request_url()).unwrap();
        assert!(url.has_host());
        assert_eq!(url.scheme(), "https");
    }
}
