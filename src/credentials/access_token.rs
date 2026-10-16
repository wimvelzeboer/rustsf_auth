//! Access token authentication module.
//!
//! This module provides functionality for authenticating with Salesforce using an existing
//! access token. It supports both simple access token authentication and refresh token
//! capabilities when additional credentials are provided.

use crate::credentials::{required, SalesforceAuthFlow, SalesforceCredentials};
use crate::error::SalesforceAuthError;
use crate::salesforce_token_response::SalesforceTokenResponse;

impl SalesforceCredentials {
	/// Creates a configuration for using an existing Salesforce access token.
	///
	/// If `refresh_token`, `client_id`, `client_secret`, and `login_url` are
	/// supplied, the resulting [`SalesforceAuthSession`] can later refresh its
	/// access token with [`SalesforceAuthSession::refresh_access_token`].
	///
	/// # Parameters
	///
	/// * `access_token` - The existing Salesforce access token
	/// * `instance_url` - The Salesforce instance URL (e.g., "https://example.my.salesforce.com")
	/// * `refresh_token` - Optional refresh token for renewing the access token
	/// * `client_id` - Optional client ID from the connected app
	/// * `client_secret` - Optional client secret from the connected app
	/// * `login_url` - Optional Salesforce login URL (e.g., "https://login.salesforce.com")
	///
	/// # Examples
	///
	/// ```rust
	/// use rustsf_auth::{SalesforceCredentials, SalesforceAuthFlow};
	///
	/// let config = SalesforceCredentials::access_token(
	///     "access-token",
	///     "https://example.my.salesforce.com",
	///     Some("refresh-token".to_string()),
	///     Some("client-id".to_string()),
	///     Some("client-secret".to_string()),
	///     Some("https://login.salesforce.com".to_string()),
	/// );
	///
	/// assert_eq!(config.flow, SalesforceAuthFlow::AccessToken);
	/// assert_eq!(config.access_token.as_deref(), Some("access-token"));
	/// ```
	///
	/// # Note
	/// An access token has a limited lifetime and will expire, since there is no refresh_token,
	/// the application will panic when its expired.
	/// Only use this authentication flow for short-lived applications
	pub fn access_token(
		access_token: impl Into<String>,
		instance_url: impl Into<String>,
		refresh_token: Option<String>,
		client_id: Option<String>,
		client_secret: Option<String>,
		login_url: Option<String>,
	) -> Self {
		Self {
			flow: SalesforceAuthFlow::AccessToken,
			login_url,
			client_id,
			client_secret,
			username: None,
			private_key_pem: None,
			access_token: Some(access_token.into()),
			refresh_token,
			instance_url: Some(instance_url.into()),
		}
	}

	/// Creates a Salesforce authentication session from an existing access token.
	///
	/// This function does not validate the access token with Salesforce. It simply
	/// wraps the token and related metadata in a [`SalesforceAuthSession`].
	///
	/// # Parameters
	///
	/// This method uses the following fields from `self`:
	/// * `access_token` - The existing Salesforce access token (required)
	/// * `login_url` - The Salesforce login URL (required)
	///
	/// # Returns
	///
	/// Returns a `Result` containing a `SalesforceTokenResponse` on success, or a
	/// `SalesforceAuthError` if required fields are missing.
	///
	/// # Examples
	///
	/// ```rust
	/// use rustsf_auth::authenticate_access_token;
	///
	/// let session = authenticate_access_token(
	///     "access-token",
	///     "https://example.my.salesforce.com/",
	///     Some("refresh-token".to_string()),
	///     Some("client-id".to_string()),
	///     Some("client-secret".to_string()),
	///     Some("https://login.salesforce.com".to_string()),
	/// );
	///
	/// assert_eq!(session.access_token, "access-token");
	/// assert_eq!(session.instance_url, "https://example.my.salesforce.com");
	/// ```
	pub(crate) fn connect_access_token(&self) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		let access_token = required(self.access_token.as_deref(), "access_token")?;
		let login_url = required(self.login_url.as_deref(), "login_url")?;

		Ok(SalesforceTokenResponse {
			access_token: access_token.to_string(),
			instance_url: Some(login_url.trim_end_matches('/').to_string()),
			id: None,
			token_type: Some("Bearer".to_string()),
			issued_at: None,
			signature: None,
			refresh_token: None,
		})
	}
}