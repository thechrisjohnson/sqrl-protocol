//! A common error used by SQRL clients and servers

use std::{fmt, num::ParseIntError, string::FromUtf8Error};

/// An error that can occur during SQRL protocol
pub struct SqrlError {
    error_message: String,
}

impl SqrlError {
    /// Create a new SqrlError with the string as error message
    pub fn new(error: String) -> Self {
        SqrlError {
            error_message: error,
        }
    }
}

impl fmt::Display for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl std::error::Error for SqrlError {}

impl From<url::ParseError> for SqrlError {
    fn from(error: url::ParseError) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<base64::DecodeError> for SqrlError {
    fn from(error: base64::DecodeError) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<FromUtf8Error> for SqrlError {
    fn from(error: FromUtf8Error) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<ParseIntError> for SqrlError {
    fn from(value: ParseIntError) -> Self {
        SqrlError::new(value.to_string())
    }
}
