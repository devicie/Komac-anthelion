use color_eyre::eyre::Report;
use napi::{Error, Status};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum ErrorCode {
    #[error("CLIENT_INITIALIZATION_FAILED")]
    ClientInitializationFailed,
    #[error("GITHUB_AUTH_REQUIRED")]
    GitHubAuthRequired,
    #[error("ANALYSIS_FAILED")]
    AnalysisFailed,
    #[error("PULL_REQUEST_LOOKUP_FAILED")]
    PullRequestLookupFailed,
    #[error("RELEASE_NOTES_FETCH_FAILED")]
    ReleaseNotesFetchFailed,
    #[error("RELEASE_NOTES_PARSE_FAILED")]
    ReleaseNotesParseFailed,
    #[error("UPDATE_FAILED")]
    UpdateFailed,
    #[error("YAML_PARSE_FAILED")]
    YamlParseFailed,
}

#[derive(Debug, Error)]
pub enum AnthelionError {
    #[error("[INVALID_ARGUMENT] {0}")]
    InvalidArgument(String),
    #[error("[{code}] {report}")]
    Failure { code: ErrorCode, report: Report },
}

pub type AnthelionResult<T> = Result<T, AnthelionError>;

impl AnthelionError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidArgument(reason.into())
    }

    pub fn failure(code: ErrorCode, report: Report) -> Self {
        Self::Failure { code, report }
    }
}

impl From<AnthelionError> for Error {
    fn from(error: AnthelionError) -> Self {
        let status = match error {
            AnthelionError::InvalidArgument(_) => Status::InvalidArg,
            AnthelionError::Failure { .. } => Status::GenericFailure,
        };
        Self::new(status, error.to_string())
    }
}
