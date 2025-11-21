use serde::{Deserialize, Serialize};

/// A tagged CBOR value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tagged<T> {
    /// The CBOR tag number (optional for compatibility)
    pub tag: Option<u64>,
    /// The tagged value
    pub value: T,
}

impl<T> Tagged<T> {
    /// Create a new tagged value
    pub fn new(tag: Option<u64>, value: T) -> Self {
        Tagged { tag, value }
    }
}
