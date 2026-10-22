//! Credentials and authentication flow management for Salesforce.
//!
//! This module provides the core types and methods for authenticating with Salesforce
//! using various OAuth 2.0 flows, including client credentials, JWT bearer, SFDX auth URLs,
//! and existing access tokens.

use std::sync::RwLock;
use std::time::Duration;
use log::trace;
use oauth2::TokenUrl;
use reqwest::Client;
use crate::{SalesforceAuthError, SalesforceAuthSession, SalesforceAuthToken};
use crate::salesforce_token_response::SalesforceTokenResponse;

mod access_token;
mod client_credentials;
mod jwt_bearer;
pub(crate) mod sfdx_auth_url;
pub mod web_server;

/// Supported Salesforce OAuth authentication flows.
///
/// This enum is used by [`SalesforceCredentials`] to decide which authentication
/// method should be executed when [`SalesforceCredentials::connect`] is called.
///
/// # Examples
///
/// ```rust
/// use rustsf_auth::SalesforceAuthFlow;
///
/// let flow = SalesforceAuthFlow::ClientCredentials;
/// assert!(matches!(flow, SalesforceAuthFlow::ClientCredentials));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SalesforceAuthFlow {
	/// Authenticate using the OAuth 2.0 client mod grant.
	ClientCredentials,

	/// Authenticate using the Salesforce JWT bearer grant.
	JwtBearer,

	/// Authenticate from an SFDX auth URL.
	SfdxUrl,

	/// Use an already available Salesforce access token.
	AccessToken,
}

/// Credentials details for authenticating to Salesforce.
///
/// This struct provides a single, convenient way to pass the required information for authentication
///
/// Prefer using one of the constructor methods below instead of manually constructing the struct.
/// - [`SalesforceCredentials::client_credentials`],
/// - [`SalesforceCredentials::jwt_bearer`],
/// - [`SalesforceCredentials::sfdx_url`],
/// - [`SalesforceCredentials::access_token`]
/// instead of manually constructing the struct.
#[derive(Debug, Clone)]
pub struct SalesforceCredentials {
	/// The authentication flow to execute.
	pub flow: SalesforceAuthFlow,

	/// Salesforce login URL, for example `https://login.salesforce.com`.
	pub login_url: Option<String>,

	/// Salesforce connected app client ID.
	pub client_id: Option<String>,

	/// Salesforce connected app client secret.
	pub client_secret: Option<String>,

	/// Salesforce username used by the JWT bearer flow.
	pub username: Option<String>,

	/// RSA private key in PEM format used by the JWT bearer flow.
	pub private_key_pem: Option<String>,

	/// Existing Salesforce access token.
	pub access_token: Option<String>,

	/// Salesforce refresh token.
	pub refresh_token: Option<String>,

	/// Salesforce instance URL, for example `https://example.my.salesforce.com`.
	pub instance_url: Option<String>,
}

impl SalesforceCredentials {

	/// Authenticates to Salesforce using the configured flow.
	///
	/// This method dispatches to one of:
	///
	/// - [`authenticate_client_credentials`]
	/// - [`authenticate_jwt_bearer`]
	/// - [`authenticate_sfdx_url`]
	/// - [`authenticate_access_token`]
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if required fields are missing, if the
	/// configured URL is invalid, if Salesforce rejects the OAuth request, or if
	/// the underlying HTTP request fails.
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	///
	/// async fn example() -> Result<(), SalesforceAuthError> {
	///     let config = SalesforceCredentials::client_credentials(
	///         "https://login.salesforce.com",
	///         "client-id",
	///         "client-secret",
	///     );
	///     let session = config.connect().await?;
	///     println!("{}", session.access_token().await?);
	///     Ok(())
	/// }
	/// ```
	///
	/// # Note
	/// The OAuth2.0 Web Server flow cannot be used with this method as that type is a two-step flow.
	pub async fn connect(self) -> Result<SalesforceAuthSession, SalesforceAuthError> {
		let token_response = self.token_response_from_flow().await?;

		let (org_id, user_id) = parse_salesforce_identity_ids(token_response.id.as_deref());

		let instance_url = match (&token_response.instance_url, &self.instance_url, &self.login_url) {
			| (Some(url), _, _ )
			| (_, Some(url), None)
			| (_, None, Some(url))
			| (_, Some(url), _) => { url },
			(_, _, _) => "http://login.salesforce.com",
		}.to_string();

		let mut credentials = self;
		if credentials.refresh_token.is_none() {
			credentials.refresh_token = token_response.refresh_token.clone();
		}

		Ok(SalesforceAuthSession {
			token: RwLock::new(SalesforceAuthToken {
				access_token: token_response.access_token,
				token_type: token_response.token_type,
				issued_at: token_response.issued_at,
				signature: token_response.signature,
			}),
			credentials,
			instance_url,
			org_id,
			user_id,
		})
	}

	/// Reconnects to Salesforce by re-executing the configured authentication flow.
	///
	/// This internal method is used to obtain a fresh access token by running the
	/// authentication flow again from scratch.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if the authentication flow fails.
	///
	/// # Examples
	///
	/// ```rust,ignore
	/// # use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	/// # async fn example() -> Result<(), SalesforceAuthError> {
	/// let credentials = SalesforceCredentials::client_credentials(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "client-secret",
	/// );
	/// let token = credentials.reconnect().await?;
	/// # Ok(())
	/// # }
	/// ```
	pub(crate) async fn reconnect(&self) -> Result<SalesforceAuthToken, SalesforceAuthError> {
		let token_response = self.token_response_from_flow().await?;
		Ok(SalesforceAuthToken::from_token_response(token_response))
	}

	/// Executes the configured authentication flow and returns the token response.
	///
	/// This internal method dispatches to the appropriate authentication method based
	/// on the configured [`SalesforceAuthFlow`].
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if the authentication flow fails.
	///
	/// # Examples
	///
	/// ```rust,ignore
	/// # use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	/// # async fn example() -> Result<(), SalesforceAuthError> {
	/// let credentials = SalesforceCredentials::client_credentials(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "client-secret",
	/// );
	/// let response = credentials.token_response_from_flow().await?;
	/// # Ok(())
	/// # }
	/// ```
	async fn token_response_from_flow(&self) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		match self.flow {
			SalesforceAuthFlow::AccessToken => self.connect_access_token(),
			SalesforceAuthFlow::ClientCredentials => self.connect_client_credentials().await,
			SalesforceAuthFlow::JwtBearer => self.connect_jwt().await,
			SalesforceAuthFlow::SfdxUrl => self.connect_sfdx_url().await,
		}
	}

	/// Refreshes the Salesforce access token using a refresh token or by reconnecting.
	///
	/// If a refresh token is available, this method uses it to obtain a new access token
	/// via the OAuth 2.0 refresh token grant. Otherwise, it falls back to reconnecting
	/// using the original authentication flow.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if the refresh token grant fails, if required
	/// fields are missing, or if the HTTP request fails.
	///
	/// # Examples
	///
	/// ```rust,ignore
	/// # use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	/// # async fn example() -> Result<(), SalesforceAuthError> {
	/// let credentials = SalesforceCredentials::client_credentials(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "client-secret",
	/// );
	/// let token = credentials.refresh().await?;
	/// println!("Access token: {}", token.access_token);
	/// # Ok(())
	/// # }
	/// ```
	pub(crate) async fn refresh(&self) -> Result<SalesforceAuthToken, SalesforceAuthError> {

		match &self.refresh_token {
			None => {
				self.reconnect().await
			}
			Some(refresh_token) => {
				let client_id = required(self.client_id.as_deref(), "client_id")?;

				let url = self.token_url()?.url().clone();
				let data = &[
					("grant_type", "refresh_token"),
					("client_id", client_id),
					("refresh_token", refresh_token),
				];
				trace!("Token exchange request: POST {} : {:?}", url, data);

				let response = Client::new()
					.post(url)
					.form(data)
					.send()
					.await?;

				let status = response.status();
				let body = response.text().await.map_err(|e| SalesforceAuthError::Http(e))?;

				trace!("Token exchange response: {}", body);
				if !status.is_success() { return Err(SalesforceAuthError::OAuth2(body)) }

				Ok(serde_json::from_str::<SalesforceAuthToken>(&body)
					   .map_err(|e| SalesforceAuthError::TokenExchange(e.to_string()))?)
			},
		}
	}

	/// Constructs the OAuth 2.0 token endpoint URL from the login URL.
	///
	/// This method builds the full token URL by appending `/services/oauth2/token`
	/// to the configured login URL.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError::MissingRequiredField`] if `login_url` is not set,
	/// or [`SalesforceAuthError::InvalidUrl`] if the constructed URL is invalid.
	///
	/// # Examples
	///
	/// ```rust,ignore
	/// # use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	/// # fn example() -> Result<(), SalesforceAuthError> {
	/// let credentials = SalesforceCredentials::client_credentials(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "client-secret",
	/// );
	/// let token_url = credentials.token_url()?;
	/// # Ok(())
	/// # }
	/// ```
	fn token_url(&self) -> Result<TokenUrl, SalesforceAuthError> {
		match &self.login_url {
			Some(login_url) => {
				let normalized = login_url.trim_end_matches('/');
				let url = format!("{normalized}/services/oauth2/token");
				Ok(TokenUrl::new(url.clone()).map_err(|source| SalesforceAuthError::InvalidUrl { url, source })?)
			}
			None => Err(SalesforceAuthError::MissingRequiredField("login_url")),
		}
	}
}


/// Creates a configured HTTP client for Salesforce API requests.
///
/// This function builds a [`reqwest::Client`] with no automatic redirects and a 30-second timeout.
///
/// # Errors
///
/// Returns [`SalesforceAuthError`] if the HTTP client cannot be built.
///
/// # Examples
///
/// ```rust,ignore
/// # use rustsf_auth::{SalesforceAuthError};
/// # use rustsf_auth::credentials::http_client;
/// # fn example() -> Result<(), SalesforceAuthError> {
/// let client = http_client()?;
/// # Ok(())
/// # }
/// ```
pub(crate) fn http_client() -> Result<reqwest::Client, SalesforceAuthError> {
	Ok(Client::builder()
		.redirect(reqwest::redirect::Policy::none())
		.timeout(Duration::from_secs(30))
		.build()?)
}


/// Validates that a required field is present.
///
/// # Parameters
///
/// * `value` - The optional field value to check
/// * `field_name` - The name of the field for error reporting
///
/// # Errors
///
/// Returns [`SalesforceAuthError::MissingRequiredField`] if `value` is `None`.
///
/// # Examples
///
/// ```rust,ignore
/// # use rustsf_auth::SalesforceAuthError;
/// # use rustsf_auth::credentials::required;
/// # fn example() -> Result<(), SalesforceAuthError> {
/// let client_id = Some("my-client-id");
/// let validated = required(client_id.as_deref(), "client_id")?;
/// assert_eq!(validated, "my-client-id");
/// # Ok(())
/// # }
/// ```
fn required<'a>(
	value: Option<&'a str>,
	field_name: &'static str,
) -> Result<&'a str, SalesforceAuthError> {
	value.ok_or(SalesforceAuthError::MissingRequiredField(field_name))
}

/// Parses the organization ID and user ID from a Salesforce identity URL.
///
/// Salesforce identity URLs have the format:
/// `https://login.salesforce.com/id/{org_id}/{user_id}`
///
/// # Parameters
///
/// * `id_url` - The optional Salesforce identity URL to parse
///
/// # Returns
///
/// A tuple of `(org_id, user_id)`, where both are `None` if the URL is invalid or missing.
///
/// # Examples
///
/// ```rust,ignore
/// # use rustsf_auth::credentials::parse_salesforce_identity_ids;
/// let url = Some("https://login.salesforce.com/id/00Dxx0000001gPLEAY/005xx000001SwiUAAS");
/// let (org_id, user_id) = parse_salesforce_identity_ids(url);
/// assert_eq!(org_id, Some("00Dxx0000001gPLEAY".to_string()));
/// assert_eq!(user_id, Some("005xx000001SwiUAAS".to_string()));
/// ```
fn parse_salesforce_identity_ids(id_url: Option<&str>) -> (Option<String>, Option<String>) {
	let Some(id_url) = id_url else {
		return (None, None);
	};

	let segments = id_url
		.trim_end_matches('/')
		.split('/')
		.filter(|segment| !segment.is_empty())
		.collect::<Vec<_>>();

	if segments.len() < 2 {
		return (None, None);
	}

	let org_id = segments
		.get(segments.len() - 2)
		.map(|value| (*value).to_string());

	let user_id = segments
		.last()
		.map(|value| (*value).to_string());

	(org_id, user_id)
}
