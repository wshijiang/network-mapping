//! Provider-independent delivery result. Only public reason codes are persisted.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub sent: bool,
    pub retryable: bool,
    pub reason: &'static str,
    pub http: Option<i32>,
    pub code: Option<i64>,
    pub retry_after: i64,
}

impl Outcome {
    pub fn failure(reason: &'static str, retryable: bool) -> Self {
        Self {
            sent: false,
            retryable,
            reason,
            http: None,
            code: None,
            retry_after: 0,
        }
    }
}
