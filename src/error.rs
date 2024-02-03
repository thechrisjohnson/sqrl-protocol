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
