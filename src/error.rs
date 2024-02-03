//! A common error used by SQRL clients and servers

use std::{fmt, num::ParseIntError, string::FromUtf8Error};

/// An error that can occur during SQRL protocol
pub struct SqrlProtocolError {
    error_message: String,
}

impl SqrlProtocolError {
    /// Create a new SqrlProtocolError with the string as error message
    pub fn new(error: String) -> Self {
        SqrlProtocolError {
            error_message: error,
        }
    }
}

impl fmt::Display for SqrlProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for SqrlProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl std::error::Error for SqrlProtocolError {}

impl From<url::ParseError> for SqrlProtocolError {
    fn from(error: url::ParseError) -> Self {
        SqrlProtocolError::new(error.to_string())
    }
}

impl From<base64::DecodeError> for SqrlProtocolError {
    fn from(error: base64::DecodeError) -> Self {
        SqrlProtocolError::new(error.to_string())
    }
}

impl From<FromUtf8Error> for SqrlProtocolError {
    fn from(error: FromUtf8Error) -> Self {
        SqrlProtocolError::new(error.to_string())
    }
}

impl From<ParseIntError> for SqrlProtocolError {
    fn from(value: ParseIntError) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}

/*impl From<std::io::Error> for SqrlProtocolError {
    fn from(error: std::io::Error) -> Self {
        SqrlProtocolError::new(error.to_string())
    }
}

impl From<std::array::TryFromSliceError> for SqrlProtocolError {
    fn from(error: std::array::TryFromSliceError) -> Self {
        SqrlProtocolError::new(error.to_string())
    }
}

impl From<InvalidParams> for SqrlProtocolError {
    fn from(value: InvalidParams) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}

impl From<InvalidOutputLen> for SqrlProtocolError {
    fn from(value: InvalidOutputLen) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}

impl From<aes_gcm::Error> for SqrlProtocolError {
    fn from(value: aes_gcm::Error) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for SqrlProtocolError {
    fn from(value: hmac::digest::InvalidLength) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for SqrlProtocolError {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        SqrlProtocolError::new(value.to_string())
    }
}*/
