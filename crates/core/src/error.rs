#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wrong key/password or tampered data. Deliberately carries no detail.
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid format: {0}")]
    Format(&'static str),
    #[error("invalid KDF parameters")]
    KdfParams,
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("invalid recovery code")]
    RecoveryCode,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
