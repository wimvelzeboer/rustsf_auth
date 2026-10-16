/// Error type returned by Salesforce authentication operations.
///
/// # Examples
///
/// ```rust
/// use rustsf_auth::{parse_sfdx_url, SalesforceAuthError};
///
/// let error = parse_sfdx_url("not-a-valid-sfdx-url").unwrap_err();
/// assert!(matches!(error, SalesforceAuthError::InvalidSfdxUrl));
/// ```

#[derive(Debug, thiserror::Error)]
pub enum SalesforceAuthError {
	#[error("missing required configuration field: {0}")]
	MissingRequiredField(&'static str),

	/// The SFDX URL did not match the required format.
	#[error("invalid SFDX URL")]
	InvalidSfdxUrl,

	/// The OAuth callback request was invalid.
	#[error("invalid OAuth callback")]
	InvalidOAuthCallback,

	/// The OAuth callback state did not match the generated state.
	#[error("OAuth state mismatch")]
	OAuthStateMismatch,

	/// A URL failed to parse.
	#[error("invalid URL `{url}`: {source}")]
	InvalidUrl {
		/// The URL string that failed to parse.
		url: String,

		/// The underlying URL parser error.
		source: url::ParseError,
	},

	/// Error returned by the `oauth2` crate.
	#[error("OAuth2 error: {0}")]
	OAuth2(String),

	/// HTTP error returned by `reqwest`.
	#[error("HTTP error: {0}")]
	Http(#[from] reqwest::Error),

	/// I/O error returned while running the local OAuth callback server.
	#[error("I/O error: {0}")]
	Io(#[from] std::io::Error),

	#[error("Token exchange failure: {0}")]
	TokenExchange(String),

	/// Error creating a Salesforce JWT assertion.
	#[error("JWT error: {0}")]
	Jwt(String),
}