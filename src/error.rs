// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

// Portions derived from serde_cbor (https://github.com/pyfisch/cbor)

use std::io;

// CBOR error type
#[derive(Debug)]
pub enum Error {
    /// IO error
    Io(io::Error),
    /// Invalid UTF-8 in string
    InvalidUtf8,
    /// Unexpected end of input
    Eof,
    /// Invalid CBOR value or syntax
    Syntax(String),
    /// Trailing data after value
    TrailingData,
    /// Error raised internally by the encoder (e.g. a value that can't be
    /// represented, or a serde call sequence the encoder doesn't support)
    Encoding(String),
    /// Custom error from a `Serialize`/`Deserialize` impl, via serde's
    /// `Error::custom` (serde compatibility)
    Serde(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8"),
            Error::Eof => write!(f, "Unexpected end of input"),
            Error::Syntax(s) => write!(f, "Syntax error: {}", s),
            Error::TrailingData => write!(f, "Trailing data"),
            Error::Encoding(s) => write!(f, "Encoding error: {}", s),
            Error::Serde(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Serde(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Serde(msg.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
