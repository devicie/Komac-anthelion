use std::sync::atomic::{AtomicBool, Ordering};

use bon::bon;
use color_eyre::eyre::Result;
use inquire::{InquireError, Password, error::InquireResult, validator::Validation};
use keyring_core::Entry;
use reqwest::{Client as ReqwestClient, StatusCode};
use reqwest_middleware::ClientWithMiddleware;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::debug;

use crate::{
    environment::CI,
    github::retry::{client as retrying_client, is_connect_error},
    http_headers::default_headers,
    prompts::handle_inquire_error,
};

const GITHUB_API_ENDPOINT: &str = "https://api.github.com/octocat";

static DEFAULT_STORE_SET: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Error)]
pub enum TokenError {
    #[error(
        "No token was provided or stored. Provide one with the `GITHUB_TOKEN` environment variable or `--token`."
    )]
    NoTokenInCI,
    #[error("GitHub token is invalid.")]
    InvalidToken,
    #[error("Failed to connect to GitHub. Please check your internet connection.")]
    FailedToConnect,
    #[error(transparent)]
    Keyring(#[from] keyring_core::Error),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    RequestMiddleware(#[from] reqwest_middleware::Error),
    #[error(transparent)]
    Inquire(#[from] InquireError),
}

pub struct TokenManager {
    token: SecretString,
}

#[bon]
impl TokenManager {
    pub async fn handle(token: Option<SecretString>) -> Result<Self, TokenError> {
        Self::resolve(token, true)
            .await?
            .ok_or(TokenError::NoTokenInCI)
    }

    /// Resolves a token in the same way as [`TokenManager::handle`], but returns `Ok(None)` rather
    /// than prompting or failing when there is no token to be found.
    ///
    /// This is for runs that only need unauthenticated, read-only access to GitHub, such as a dry
    /// run that writes manifests out locally instead of submitting them.
    pub async fn handle_optional(token: Option<SecretString>) -> Result<Option<Self>, TokenError> {
        Self::resolve(token, false).await
    }

    async fn resolve(
        token: Option<SecretString>,
        required: bool,
    ) -> Result<Option<Self>, TokenError> {
        // Token rules:
        // - If caller passed `--token`: validate it and fail if invalid.
        // - Otherwise try the platform's credential store. An unusable store (a headless Linux
        //   machine with no D-Bus session, for example) is treated as having no stored token.
        //     * In CI: if no token or if stored token is invalid -> error (never prompt).
        //     * Interactive: if no stored token or stored token is invalid -> prompt and store.
        // - If a token isn't `required`, no token at all is fine and nothing is prompted for.

        let client = retrying_client(
            ReqwestClient::builder()
                .default_headers(default_headers(None))
                .build()?,
        );

        let token_passed = token.is_some();

        let credential = if token_passed {
            None
        } else {
            // A credential store that can't be opened is not fatal - the token can still come from
            // `--token`, `GITHUB_TOKEN`, or a prompt. CI runners routinely have no credential
            // store at all, so don't even mention it there.
            Self::credential()
                .inspect_err(|error| {
                    if !*CI {
                        debug!(%error, "Failed to open the credential store");
                    }
                })
                .ok()
        };

        let token = if let Some(token) = token {
            Some(token)
        } else if let Some(ref credential) = credential {
            match credential.get_password() {
                Ok(token) => Some(SecretString::new(token.into_boxed_str())),
                Err(keyring_core::Error::NoEntry) => None, // No stored token
                Err(error) => {
                    if !*CI {
                        debug!(%error, "Failed to read the stored token");
                    }
                    None
                }
            }
        } else {
            None
        };

        if let Some(token) = token {
            match Self::validate(&client, token.expose_secret()).await {
                Ok(()) => return Ok(Some(Self { token })),
                Err(TokenError::InvalidToken) if token_passed => {
                    return Err(TokenError::InvalidToken);
                }
                Err(TokenError::InvalidToken) if *CI => {
                    if required {
                        return Err(TokenError::InvalidToken);
                    }
                    return Ok(None);
                }
                Err(TokenError::InvalidToken) => {}
                Err(err) => return Err(err),
            }
        }

        // There's no usable token, and a prompt can't be answered in CI or when a token is optional.
        if !required || *CI {
            return Ok(None);
        }

        let validated_token = Self::prompt().client(&client).call()?;

        if let Some(credential) = credential
            && credential
                .set_password(validated_token.expose_secret())
                .is_ok()
        {
            println!("Successfully stored token in platform's secure storage");
        }

        Ok(Some(Self {
            token: validated_token,
        }))
    }

    #[builder]
    pub fn prompt(
        client: &ClientWithMiddleware,
        #[builder(default = "Enter a GitHub token")] message: &str,
    ) -> InquireResult<SecretString> {
        tokio::task::block_in_place(|| {
            let rt = Handle::current();
            let client = client.clone();
            let validator = move |input: &str| match rt
                .block_on(async { Self::validate(&client, input).await })
            {
                Ok(()) => Ok(Validation::Valid),
                Err(err) => Ok(Validation::Invalid(err.into())),
            };

            Password::new(message)
                .with_validator(validator)
                .without_confirmation()
                .prompt()
                .map(|token| SecretString::new(token.into_boxed_str()))
                .map_err(handle_inquire_error)
        })
    }

    pub async fn validate(client: &ClientWithMiddleware, token: &str) -> Result<(), TokenError> {
        match client
            .get(GITHUB_API_ENDPOINT)
            .bearer_auth(token)
            .send()
            .await
        {
            Ok(response) => match response.status() {
                StatusCode::UNAUTHORIZED => Err(TokenError::InvalidToken),
                _ => Ok(()),
            },
            Err(error) => {
                if is_connect_error(&error) {
                    Err(TokenError::FailedToConnect)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    /// Returns komac's named entry in a credential store.
    pub fn credential() -> keyring_core::Result<Entry> {
        const SERVICE: &str = "komac";
        const USERNAME: &str = "github-access-token";

        if !DEFAULT_STORE_SET.load(Ordering::Relaxed) {
            keyring_core::set_default_store(cfg_select! {
                target_os = "windows" => windows_native_keyring_store::Store::new()?,
                any(target_os = "linux", target_os = "freebsd", target_os = "openbsd") => {
                    dbus_secret_service_keyring_store::Store::new()?
                },
                target_os = "macos" => apple_native_keyring_store::keychain::Store::new()?,
            });

            DEFAULT_STORE_SET.store(true, Ordering::Relaxed);
        }

        Entry::new(SERVICE, USERNAME)
    }

    pub fn unset_default_store() {
        if DEFAULT_STORE_SET.load(Ordering::Relaxed) {
            keyring_core::unset_default_store();
        }
    }

    #[inline]
    pub fn into_token(self) -> SecretString {
        self.token
    }
}

impl AsRef<SecretString> for TokenManager {
    fn as_ref(&self) -> &SecretString {
        &self.token
    }
}

impl From<TokenManager> for SecretString {
    #[inline]
    fn from(token_manager: TokenManager) -> Self {
        token_manager.into_token()
    }
}
