//! OAuth 2.0 Client Credentials flow implementation for Salesforce authentication.
//!
//! This module provides functionality to authenticate with Salesforce using the
//! OAuth 2.0 Client Credentials grant type, which is suitable for server-to-server
//! integrations where no user interaction is required.

use log::trace;
use secrecy::{ExposeSecret, SecretString};
use crate::credentials::{http_client, required, SalesforceAuthFlow, SalesforceCredentials};
use crate::salesforce_token_response::SalesforceTokenResponse;
use crate::SalesforceAuthError;

impl SalesforceCredentials {
	/// Connects to Salesforce using the OAuth 2.0 Client Credentials flow.
	///
	/// # Parameters
	///
	/// - `login_url`: The Salesforce login url, e.g. `https://login.salesforce.com`
	/// - `client_id`: The Connected App Client Id
	/// - `client_secret`: The Connected App Client Secret
	///
	/// # Example
	///
	/// ```rust, ignore
	/// use oauth2::http::header::AUTHORIZATION;
	///	use oauth2::http::{HeaderMap, HeaderValue};
	///	use rustsf_auth::SalesforceCredentials;
	///
	///    pub const CONNECT_TIMEOUT: u64 = 15;
	///    pub const REQUEST_TIMEOUT: u64 = 30;
	///    #[tokio::main]
	///    async fn main(){
	/// 	// The client id and secret, (should never be hardcoded)
	/// 	let login_url = "https://example.my.salesforce.com/";
	/// 	let client_id = "client_id";
	/// 	let client_secret = "client_secret";
	///
	/// 	// The Credentials configuration
	/// 	let config = SalesforceCredentials::client_credentials(
	/// 		login_url,
	/// 		client_id,
	/// 		client_secret);
	///
	/// 	// Constructing the authentication session and connecting to Salesforce
	/// 	let session = config.connect().await.unwrap();
	///
	/// 	// Build the headers to include the access token
	/// 	let mut headers = HeaderMap::new();
	/// 	let auth_value = format!("Bearer {}", session.access_token().await.unwrap());
	/// 	headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());
	///
	/// 	// A REST API request
	/// 	let response = reqwest::Client::builder()
	/// 		.redirect(reqwest::redirect::Policy::none())
	/// 		.connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT))
	/// 		.timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT))
	/// 		.build()
	/// 		.unwrap()
	/// 		.get(format!("{}/services/data", session.instance_url))
	/// 		.headers(headers)
	/// 		.send()
	/// 		.await
	/// 		.unwrap();
	///
	/// 	if response.status().is_success() {
	/// 		println!("SUCCESS Response: {:?}", response.text().await.unwrap());
	/// 	} else {
	/// 		println!("ERROR Response: {:?}", response.text().await.unwrap());
	/// 	}
	///    }
	/// ```
	pub fn client_credentials(
		login_url: impl Into<String>,
		client_id: impl Into<String>,
		client_secret: impl Into<String>,
	) -> Self {
		Self {
			flow: SalesforceAuthFlow::ClientCredentials,
			login_url: Some(login_url.into()),
			client_id: Some(client_id.into()),
			client_secret: Some(SecretString::new(Box::from(client_secret.into()))),
			username: None,
			private_key_pem: None,
			access_token: None,
			refresh_token: None,
			instance_url: None,
		}
	}

	/// Authenticates to Salesforce using the OAuth 2.0 Client Credentials flow.
	///
	/// This method sends a client credentials token request to:
	///
	/// `{login_url}/services/oauth2/token`
	///
	/// # Parameters
	///
	/// This method uses the following fields from `self`:
	/// - `client_id` - The Connected App Client ID (required)
	/// - `client_secret` - The Connected App Client Secret (required)
	/// - `login_url` - The Salesforce login URL (required)
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if:
	/// - Required fields (`client_id`, `client_secret`, or `login_url`) are missing
	/// - The HTTP request fails
	/// - Salesforce rejects the token request
	/// - The response cannot be parsed
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::{SalesforceCredentials, SalesforceAuthError};
	///
	/// # async fn example() -> Result<(), SalesforceAuthError> {
	/// let credentials = SalesforceCredentials::client_credentials(
	///     "https://login.salesforce.com",
	///     "your-client-id",
	///     "your-client-secret",
	/// );
	///
	/// let session = credentials.connect().await?;
	/// println!("Access token: {}", session.access_token().await?);
	/// # Ok(())
	/// # }
	/// ```
	pub(crate) async fn connect_client_credentials(&self) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		let client_id = required(self.client_id.as_deref(), "client_id")?;
		let client_secret = required(self.client_secret.as_ref().map(|s| s.expose_secret()), "client_secret")?;

		let url = self.token_url()?.url().clone();
		let data = &[
			("grant_type", "client_credentials"),
			("client_id", client_id),
			("client_secret", client_secret),
		];
		trace!("Client Credentials auth request: POST {}", url);

		let response = http_client()?
			.post(url)
			.form(data)
			.send()
			.await?;

		let status = response.status();
		let body = response.text().await.map_err(|e| SalesforceAuthError::Http(e))?;

		trace!("Client Credentials auth response: {}", body);
		if !status.is_success() { return Err(SalesforceAuthError::OAuth2(body)); }

		Ok(serde_json::from_str::<SalesforceTokenResponse>(&body)
			.map_err(|e| SalesforceAuthError::TokenExchange(e.to_string()))?)
	}
}