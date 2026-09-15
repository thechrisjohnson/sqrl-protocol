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

impl From<SqrlUrlError> for SqrlError {
    fn from(value: SqrlUrlError) -> Self {
        SqrlError::new(format!("Invalid Sqrl Url : {}", value))
    }
}

/// Represents an error that can occur while attempting to parse a SqrlUrl
#[derive(Debug)]
#[non_exhaustive]
pub enum SqrlUrlError {
    /// The encoded url is missing
    MissingEncodedUrl,
    /// The encoded url is too long
    EncodedUrlTooLong,
    /// Invalid base64 encoding
    InvalidBase64,
    /// Invalid UTF8 characters
    InvalidUtf8,
    /// Invalid url
    InvalidUrl,
    /// Unsupported schemed type
    UnsupportedScheme,
    /// The url is missing a host field
    MissingHost,
    /// The url is missing a nut paramete
    MissingNut,
    /// Duplicate parameter values
    DuplicateParameter(String),
    /// Invalid cancel url
    InvalidCancelUrl,
    /// Invalid path extension
    InvalidPathExtension,
    /// Path extension value out of range
    PathExtensionOutOfRange,
}

impl fmt::Display for SqrlUrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SqrlUrlError::MissingEncodedUrl => write!(f, "The encoded url is missing"),
            SqrlUrlError::EncodedUrlTooLong => write!(f, "The encoded url is too long"),
            SqrlUrlError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            SqrlUrlError::InvalidUtf8 => write!(f, "Invalid UTF8 characters"),
            SqrlUrlError::InvalidUrl => write!(f, "Invalid url"),
            SqrlUrlError::UnsupportedScheme => write!(f, "Unsupported schemed type"),
            SqrlUrlError::MissingHost => write!(f, "The url is missing a host field"),
            SqrlUrlError::MissingNut => write!(f, "The url is missing a nut parameter"),
            SqrlUrlError::DuplicateParameter(p) => {
                write!(f, "Duplicate parameter values for {}", p)
            }
            SqrlUrlError::InvalidCancelUrl => write!(f, "Invalid cancel url"),
            SqrlUrlError::InvalidPathExtension => write!(f, "Invalid path extension"),
            SqrlUrlError::PathExtensionOutOfRange => write!(f, "Path extension value out of range"),
        }
    }
}

impl std::error::Error for SqrlUrlError {}
