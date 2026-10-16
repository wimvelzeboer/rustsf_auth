//! # RustSF Auth
//!
//! Salesforce authentication SDK for Rust, supporting the OAuth2.0 flows:
//! - [Client Credentials](crate::credentials::SalesforceCredentials#method.client_credentials)
//! - JWT,
//! - [sfdxAuthUrl](crate::credentials::SalesforceCredentials#method.sfdx_url),
//! - [Web Server](crate::credentials::web_server::OAuthWebService#method.authorization_url),
//!   (this two-step flow lets a user authentiate via a browser)

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub mod credentials;
pub mod error;
pub(crate) mod salesforce_auth_token;
pub mod salesforce_token_response;

pub use self::error::SalesforceAuthError;
use self::salesforce_auth_token::SalesforceAuthToken;

pub use self::credentials::{SalesforceAuthFlow, SalesforceCredentials};
pub use self::credentials::sfdx_auth_url::SfdxAuthJson;
pub use self::credentials::web_server::OAuthWebService;

/// The default Salesforce production login URL.
///
/// Use this value when authenticating against a production Salesforce org.
///
/// # Examples
///
/// ```rust
/// use rustsf_auth::DEFAULT_SALESFORCE_LOGIN_URL;
///
/// assert_eq!(DEFAULT_SALESFORCE_LOGIN_URL, "https://login.salesforce.com");
/// ```
pub const DEFAULT_SALESFORCE_LOGIN_URL: &str = "https://login.salesforce.com";


/// Authenticated Salesforce session data.
///
/// This struct contains the access token and Salesforce instance URL returned
/// by Salesforce, along with optional metadata such as the refresh token and
/// connected app mod.
///
/// # Examples
///
/// ```rust
/// use rustsf_auth::authenticate_access_token;
///
/// let session = authenticate_access_token(
///     "access-token",
///     "https://example.my.salesforce.com",
///     None,
///     None,
///     None,
///     None,
/// );
///
/// assert_eq!(session.access_token(), "access-token");
/// ```
#[derive(Debug)]
pub struct SalesforceAuthSession {
	token: RwLock<SalesforceAuthToken>,

	/// Authentication flow used to create this session.
	pub credentials: SalesforceCredentials,

	/// Salesforce instance URL associated with the authenticated org.
	pub instance_url: String,

	/// OAuth refresh token, when available.
	/// Salesforce organization ID parsed from the identity service URL.
	pub org_id: Option<String>,

	/// Salesforce user ID parsed from the identity service URL.
	pub user_id: Option<String>,
}

impl SalesforceAuthSession {

	fn token_read(&self) -> RwLockReadGuard<'_, SalesforceAuthToken> {
		self.token
			.read()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	fn token_write(&self) -> RwLockWriteGuard<'_, SalesforceAuthToken> {
		self.token
			.write()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	fn token(&self) -> SalesforceAuthToken {
		self.token_read().clone()
	}

	pub async fn access_token(&self) -> Result<String, SalesforceAuthError> {
		if self.token_read().is_expired() {
			self.refresh_access_token().await?;
		}

		Ok(self.token_read().access_token())
	}

	pub fn token_type(&self) -> Option<String> {
		self.token().token_type
	}

	pub fn issued_at(&self) -> Option<String> {
		self.token().issued_at
	}

	pub fn signature(&self) -> Option<String> {
		self.token().signature
	}


	/// Refreshes this session's access token.
	///
	/// The session must contain `login_url`, `client_id`, and `refresh_token`.
	/// `client_secret` is optional because Salesforce connected apps may be
	/// configured without requiring a secret for refresh.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError::MissingField`] if required refresh fields
	/// are absent. Returns other [`SalesforceAuthError`] variants if the refresh
	/// request fails.
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::authenticate_access_token;
	///
	/// # async fn example() -> Result<(), rustsf_auth::SalesforceAuthError> {
	/// let session = authenticate_access_token(
	///     "old-access-token",
	///     "https://example.my.salesforce.com",
	///     Some("refresh-token".to_string()),
	///     Some("client-id".to_string()),
	///     Some("client-secret".to_string()),
	///     Some("https://login.salesforce.com".to_string()),
	/// );
	///
	/// let refreshed = session.refresh_access_token().await?;
	/// println!("{}", refreshed.access_token);
	/// # Ok(())
	/// # }
	/// ```
	pub async fn refresh_access_token(&self) -> Result<(), SalesforceAuthError> {

		let token = self.credentials.refresh().await?;
		*self.token_write() = token;

		Ok(())
	}
}


fn salesforce_token_endpoint(login_url: &str) -> String {
	format!("{}/services/oauth2/token", login_url.trim_end_matches('/'))
}
/*

#[cfg(test)]
mod tests {
	use super::*;
	use httpmock::Method::POST;
	use httpmock::MockServer;
	use serde_json::json;

	fn token_body() -> serde_json::Value {
		json!({
            "access_token": "access-token-123",
            "instance_url": "https://example.my.salesforce.com",
            "id": "https://login.salesforce.com/id/00D/example",
            "token_type": "Bearer",
            "issued_at": "1700000000000",
            "signature": "signature"
        })
	}

	#[test]
	fn parses_valid_sfdx_url_with_secret() {
		let parsed = parse_sfdx_url(
			"force://client.id:client.secret:refresh_token==@login.salesforce.com",
		)
			.unwrap();

		assert_eq!(parsed.client_id, "client.id");
		assert_eq!(parsed.client_secret, Some("client.secret".to_string()));
		assert_eq!(parsed.refresh_token, "refresh_token==");
		assert_eq!(parsed.login_url, "https://login.salesforce.com");
	}

	#[test]
	fn parses_valid_sfdx_url_without_secret() {
		let parsed = parse_sfdx_url(
			"force://client_id::refresh-token@sandbox.my.salesforce.com",
		)
			.unwrap();

		assert_eq!(parsed.client_id, "client_id");
		assert_eq!(parsed.client_secret, None);
		assert_eq!(parsed.refresh_token, "refresh-token");
		assert_eq!(parsed.login_url, "https://sandbox.my.salesforce.com");
	}

	#[test]
	fn rejects_invalid_sfdx_url() {
		let result = parse_sfdx_url("https://not-a-force-url");

		assert!(matches!(result, Err(SalesforceAuthError::InvalidSfdxUrl)));
	}

	#[test]
	fn authenticates_existing_access_token() {
		let session = authenticate_access_token(
			"access-token",
			"https://example.my.salesforce.com/",
			Some("refresh-token".to_string()),
			Some("client-id".to_string()),
			Some("client-secret".to_string()),
			Some("https://login.salesforce.com".to_string()),
		);

		assert_eq!(session.access_token, "access-token");
		assert_eq!(session.instance_url, "https://example.my.salesforce.com");
		assert_eq!(session.refresh_token, Some("refresh-token".to_string()));
		assert_eq!(session.client_id, Some("client-id".to_string()));
	}

	/*#[tokio::test]
	async fn refreshes_access_token() {
		let server = MockServer::start();

		let mock = server.mock(|when, then| {
			when.method(POST)
				.path("/services/oauth2/token")
				.body_contains("grant_type=refresh_token")
				.body_contains("client_id=client-id")
				.body_contains("refresh_token=refresh-token")
				.body_contains("client_secret=client-secret");

			then.status(200)
				.header("content-type", "application/json")
				.json_body(token_body());
		});

		let session = refresh_access_token(
			&server.base_url(),
			"client-id",
			Some("client-secret"),
			"refresh-token",
		)
			.await
			.unwrap();

		mock.assert();

		assert_eq!(session.access_token, "access-token-123");
		assert_eq!(session.instance_url, "https://example.my.salesforce.com");
		assert_eq!(session.refresh_token, Some("refresh-token".to_string()));
		assert_eq!(session.client_id, Some("client-id".to_string()));
		assert_eq!(session.client_secret, Some("client-secret".to_string()));
	}*/

	#[tokio::test]
	async fn authenticates_with_sfdx_url() {
		let server = MockServer::start();
		let login_endpoint = server.base_url().trim_start_matches("http://");

		let mock = server.mock(|when, then| {
			when.method(POST)
				.path("/services/oauth2/token")
				.body_contains("grant_type=refresh_token")
				.body_contains("client_id=client_id")
				.body_contains("refresh_token=refresh-token")
				.body_contains("client_secret=client_secret");

			then.status(200)
				.header("content-type", "application/json")
				.json_body(token_body());
		});

		let sfdx_url = format!(
			"force://client_id:client_secret:refresh-token@{}",
			login_endpoint
		);

		let session = authenticate_sfdx_url(&sfdx_url).await.unwrap();

		mock.assert();

		assert_eq!(session.access_token, "access-token-123");
		assert_eq!(session.client_id, Some("client_id".to_string()));
		assert_eq!(session.client_secret, Some("client_secret".to_string()));
		assert_eq!(session.refresh_token, Some("refresh-token".to_string()));
	}

	#[tokio::test]
	async fn authenticates_jwt_bearer_with_mocked_server() {
		let server = MockServer::start();

		let private_key = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuG+lZLtnnpGIpi19j9vYTsMprthOKAlrdbL1xSdFypPe6KQm
Eu+/bywT79seAyVOg8cmZD98vrTGkYVOEZ18FaXpgFrH/dYRkUSr7UNpZvCE1z1l
Kw/I31QglVC5YACxoxAJ3jgy5bPG9YRVBzsvtvUfxTRMfl01nVNQf7M08KvAl9Ur
IcS67JVKqgJhjY6DShMk94U6ZFhReZR0aoXMN9nhAeJ7KxIuMuENyzdIArHnqijH
yYuSNxiVcCT5qV+6kPnwouyBUbZnqjoMzOls3hVjSR//TQlajfX5aaG/MQCMuFlr
wYoXF75A/cQHlcJzucYi9qSt8k1mKx8/rBY+iQIDAQABAoIBABWmZGQGM8H3mfIy
sWCVBCDnJJr34OjaUJFYihUac0uCRJo76iMcG2hFYyD9H8+B6uDpUy0Js25v0lpb
gVUeASidIcbIGCtsfdb2yyGYWcBN1ZQSrxtZV1iz3X3U5PpQ/dwLx+tmL7PTUR7Y
x+v9vyNdZwE8iqaGwO0csnl8leRYOvPP2ZEBx16aMl+lviuN+ephtU7avPEU3MDV
vtEX8f+P0B25NRasEnX7oH7xwhA0me6cfWAhw3tKBpEzHcKyXnP6EJJvvxTYdjr+
JeunHPw4H3o6FlblMvvC9OF9xboq4lGxgcjdvCSji1TLlvNGjvpcpYPWlSKzMD1G
bWkB/QECgYEA5k5aosZbaLG0WBSX/Dby0EP3SWhSLuz6Qc5GZei5Pq12aXnbgnZR
k0OiZtxg5D+50ZyLzVC7T4y/NfaAVLO0wj0yM01Q9PrP/htIBaE+fjDUJpqE0um2
bcxN0ZAKi82wKjUsnPRtyv0J3mDA3rQSjv8MW3QoM4l/XwwWfbJUjRkCgYEAzQ5s
efnKwDXJmzsNBMP4k9MUiOkFZoNg47UW97HvxUGd5jjJHdg91WovRuIi0GpeO2BO
lAaQwNvNHCLQVEV9hvYtPSFsKLYSR7qD6yzfvx3e+e0tY/KRnssSgIoOucONWRCM
MQkDWhe/WVc5yu/zmDpqQu5ZhKGecCWIrFsXstUCgYEAyptC1fmE8K7KI/pAJBX9
TvG2GgsI1Fu5V+8FIxZo+Xdu/8SH38mBrlgnYiPbKmYNbVKPSgFw4eu+vt0G9+61
vGZMhS+oBj4zFNN+wBvGslNCLdxUNLGhSvTMiN7ayRnS91ecFaMFO2tXLeXsbGpW
QT+BKwDQP47jm5xvWcOMmukCgYATvhwxfQUCHSwLURXZxK4z8K4yHBHujvcJJ8rC
4RrDiUv9gglAWtlMDAUt+YefZewA0ahxVBQgRpgndQrw0hBPn5MOO2X25O/NaWIr
xV1HOx+kgwv68s43WlVsnfpP/4eJeAUPOqpUWkaqWt+Rh/lQmkljPzCWO50NFesx
jJhWtQKBgQDGeJFyGAQ8RJCnzp9Lmhu8oayGjra/N/0mJ41eNxmF9muHfJvEK8hf
O+fFkSBwBf0RGpsaqlzEjOeuGk6nza0tKi9gXR/iVwpDAWx5p++xuKHmr0u6BzWN
iPVvh9x50hP1hS1U1WlZTNhmFLj1gCwCKPwqZzIgVjWgltxO8+/ftA==
-----END RSA PRIVATE KEY-----"#;

		let mock = server.mock(|when, then| {
			when.method(POST)
				.path("/services/oauth2/token")
				.body_contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
				.body_contains("assertion=");

			then.status(200)
				.header("content-type", "application/json")
				.json_body(token_body());
		});

		let session = authenticate_jwt_bearer(
			&server.base_url(),
			"client-id",
			"user@example.com",
			private_key,
		)
			.await
			.unwrap();

		mock.assert();

		assert_eq!(session.access_token, "access-token-123");
		assert_eq!(session.instance_url, "https://example.my.salesforce.com");
		assert_eq!(session.client_id, Some("client-id".to_string()));
	}

	#[tokio::test]
	async fn config_authenticates_access_token_flow() {
		let config = SalesforceCredentials::access_token(
			"access-token",
			"https://example.my.salesforce.com",
			None,
			None,
			None,
			Some("https://computing-platform-9537--qa.sandbox.my.salesforce.com/".to_string()),
		);

		let session = config.connect().await.unwrap();

		assert_eq!(session.access_token, "access-token");
		assert_eq!(session.instance_url, "https://example.my.salesforce.com");
	}
}
*/