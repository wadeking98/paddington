use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("Could not decrypt using classic padding oracle attack: {0}")]
    CouldNotDecryptClassic(String),
    #[error("Invalid input when preforming padding oracle attack: {0}")]
    InvalidInput(String),
    #[error("Error when comparing responses for padding oracle attack: {0}")]
    DifferentialResponses(String),
}
