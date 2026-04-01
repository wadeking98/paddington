use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("Could not decrypt using classic padding oracle attack: {0}")]
    CouldNotDecryptClassic(String),
    #[error("Invalid input when preforming padding oracle attack: {0}")]
    InvalidInput(String),
    #[error("Error when comparing responses for padding oracle attack: {0}")]
    DifferentialResponses(String),
    #[error("Error when performing bad byte attack, you likely provided incorrect bad bytes: {0}")]
    BadByteIssue(String),
    #[error(
        "Error when building cradle, there may be too many invalid characters to feasibly exploit the oracle: {0}"
    )]
    CradleBuildIssue(String),
    #[error("Error when establishing baseline")]
    BaselineError(),
}
