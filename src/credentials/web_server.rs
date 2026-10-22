use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use log::trace;
use oauth2::TokenUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::credentials::{
	http_client, parse_salesforce_identity_ids, SalesforceAuthFlow, SalesforceCredentials,
};
use crate::salesforce_token_response::SalesforceTokenResponse;
use crate::{SalesforceAuthError, SalesforceAuthSession, SalesforceAuthToken};

const DEFAULT_WEB_SERVER_SCOPES: &[&str] = &["api", "refresh_token", "offline_access"];

const DEFAULT_CALLBACK_RESPONSE: &str = concat!(
"<!doctype html>",
"<html>",
"<head><title>Salesforce Login Complete</title></head>",
"<body>",
"<h1>Salesforce login complete</h1>",
"<p>You can close this browser window and return to your application.</p>",
"</body>",
"</html>"
);

/// OAuth 2.0 Web Server Flow helper.
///
/// This type prepares a Salesforce authorization URL, lets the caller decide how
/// to open it, then listens for the OAuth callback and exchanges the received
/// authorization code for a Salesforce session.
#[derive(Debug, Clone)]
pub struct OAuthWebService {
	login_url: String,
	client_id: String,
	client_secret: Option<String>,
	redirect_uri: String,
	scopes: Vec<String>,
	state: String,
	callback_response: Option<String>,
}

impl OAuthWebService {
	/// Creates a new OAuth Web Server Flow helper.
	///
	/// The caller should call [`OAuthWebService::authorization_url`] first, open
	/// the returned URL in a browser, then call [`OAuthWebService::connect`] to
	/// wait for the callback and receive a [`SalesforceAuthSession`].
	///
	/// # Parameters
	///
	/// - `login_url`: Salesforce login URL (e.g., `https://login.salesforce.com`)
	/// - `client_id`: Connected app client ID
	/// - `client_secret`: Optional connected app client secret
	/// - `redirect_uri`: OAuth callback URL (e.g., `http://localhost:8080/callback`)
	/// - `scopes`: Optional list of OAuth scopes. Defaults to `["api", "refresh_token", "offline_access"]`
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::credentials::web_server::OAuthWebService;
	///
	/// let service = OAuthWebService::new(
	///     "https://login.salesforce.com",
	///     "my-client-id",
	///     Some("my-client-secret".to_string()),
	///     "http://localhost:8080/callback",
	///     None,
	/// );
	/// ```
	pub fn new(
		login_url: impl Into<String>,
		client_id: impl Into<String>,
		client_secret: Option<String>,
		redirect_uri: impl Into<String>,
		scopes: Option<Vec<String>>,
	) -> Self {
		Self {
			login_url: login_url.into(),
			client_id: client_id.into(),
			client_secret,
			redirect_uri: redirect_uri.into(),
			scopes: scopes.unwrap_or_else(|| {
				DEFAULT_WEB_SERVER_SCOPES
					.iter()
					.map(|scope| (*scope).to_string())
					.collect()
			}),
			state: create_state(),
			callback_response: None,
		}
	}

	/// Builds the Salesforce authorization URL.
	///
	/// This method does not open a browser. The caller is responsible for opening
	/// the returned URL or presenting it to the user.
	///
	/// # Returns
	///
	/// Returns the authorization URL that the user should visit to grant access.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError::InvalidUrl`] if the login URL cannot be parsed.
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::credentials::web_server::OAuthWebService;
	///
	/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
	/// let service = OAuthWebService::new(
	///     "https://login.salesforce.com",
	///     "my-client-id",
	///     None,
	///     "http://localhost:8080/callback",
	///     None,
	/// );
	///
	/// let auth_url = service.authorization_url().await?;
	/// println!("Visit this URL: {}", auth_url);
	/// # Ok(())
	/// # }
	/// ```
	pub async fn authorization_url(&self) -> Result<String, SalesforceAuthError> {
		let normalized = self.login_url.trim_end_matches('/');
		let authorize_url = format!("{normalized}/services/oauth2/authorize");

		let mut url = Url::parse(&authorize_url)
			.map_err(|source| SalesforceAuthError::InvalidUrl {
				url: authorize_url,
				source,
			})?;

		url.query_pairs_mut()
			.append_pair("response_type", "code")
			.append_pair("client_id", &self.client_id)
			.append_pair("redirect_uri", &self.redirect_uri)
			.append_pair("scope", &self.scopes.join(" "))
			.append_pair("state", &self.state)
			.append_pair("prompt", "login");

		Ok(url.to_string())
	}

	/// Starts listening for the OAuth callback and exchanges the authorization
	/// code for a Salesforce authentication session.
	///
	/// Call [`OAuthWebService::authorization_url`] first and open that URL in a
	/// browser before awaiting this method.
	///
	/// # Returns
	///
	/// Returns a [`SalesforceAuthSession`] containing the access token and other
	/// authentication details.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if:
	/// - The redirect URI is invalid or missing a port
	/// - The TCP listener cannot be bound
	/// - The OAuth callback is malformed
	/// - The state parameter doesn't match
	/// - Token exchange with Salesforce fails
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::credentials::web_server::OAuthWebService;
	///
	/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
	/// let service = OAuthWebService::new(
	///     "https://login.salesforce.com",
	///     "my-client-id",
	///     Some("my-client-secret".to_string()),
	///     "http://localhost:8080/callback",
	///     None,
	/// );
	///
	/// let auth_url = service.authorization_url().await?;
	/// println!("Visit this URL: {}", auth_url);
	/// // User opens the URL in a browser and authorizes
	///
	/// let session = service.connect().await?;
	/// println!("Access token: {}", session.access_token().await?);
	/// # Ok(())
	/// # }
	/// ```
	pub async fn connect(&self) -> Result<SalesforceAuthSession, SalesforceAuthError> {
		let callback_url = Url::parse(&self.redirect_uri)
			.map_err(|source| SalesforceAuthError::InvalidUrl {
				url: self.redirect_uri.clone(),
				source,
			})?;

		let host = callback_url.host_str().unwrap_or("127.0.0.1");
		let port = callback_url
			.port_or_known_default()
			.ok_or(SalesforceAuthError::MissingRequiredField("redirect_uri port"))?;

		let bind_host = if host == "localhost" { "127.0.0.1" } else { host };
		let listener = TcpListener::bind((bind_host, port)).await?;

		let callback = receive_oauth_callback(
			listener,
			self.callback_response.as_deref(),
		).await?;

		let callback_state = callback
			.get("state")
			.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;

		if callback_state != &self.state {
			return Err(SalesforceAuthError::OAuthStateMismatch);
		}

		let code = callback
			.get("code")
			.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;

		let token_response = self.exchange_authorization_code(code).await?;

		self.session_from_token_response(token_response)
	}

	/// Sets the HTML response returned to the browser after Salesforce redirects
	/// back to the local OAuth callback listener.
	///
	/// If this method is not called, a default "Salesforce login complete" page is
	/// returned.
	///
	/// # Parameters
	///
	/// - `response`: HTML content to display in the browser after successful authentication
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// use rustsf_auth::credentials::web_server::OAuthWebService;
	///
	/// let custom_html = r#"<!doctype html>
	/// <html>
	/// <head><title>Success</title></head>
	/// <body><h1>Authentication successful!</h1></body>
	/// </html>"#;
	///
	/// let service = OAuthWebService::new(
	///     "https://login.salesforce.com",
	///     "my-client-id",
	///     None,
	///     "http://localhost:8080/callback",
	///     None,
	/// ).with_callback_response(custom_html);
	/// ```
	pub fn with_callback_response(mut self, response: impl Into<String>) -> Self {
		self.callback_response = Some(response.into());
		self
	}

	async fn exchange_authorization_code(
		&self,
		code: &str,
	) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		let url = self.token_url()?.url().clone();

		let mut data = vec![
			("grant_type", "authorization_code"),
			("code", code),
			("client_id", self.client_id.as_str()),
			("redirect_uri", self.redirect_uri.as_str()),
		];

		if let Some(client_secret) = self.client_secret.as_deref() {
			data.push(("client_secret", client_secret));
		}

		trace!("Web Server Flow token exchange request: POST {}", url);

		let response = http_client()?
			.post(url)
			.form(&data)
			.send()
			.await?;

		let status = response.status();
		let body = response.text().await.map_err(SalesforceAuthError::Http)?;

		trace!("Web Server Flow token exchange response: {}", body);

		if !status.is_success() {
			return Err(SalesforceAuthError::OAuth2(body));
		}

		Ok(serde_json::from_str::<SalesforceTokenResponse>(&body)
			.map_err(|e| SalesforceAuthError::TokenExchange(e.to_string()))?)
	}

	fn session_from_token_response(
		&self,
		token_response: SalesforceTokenResponse,
	) -> Result<SalesforceAuthSession, SalesforceAuthError> {
		let (org_id, user_id) = parse_salesforce_identity_ids(token_response.id.as_deref());

		let instance_url = token_response
			.instance_url
			.clone()
			.unwrap_or_else(|| self.login_url.trim_end_matches('/').to_string());

		let credentials = SalesforceCredentials {
			flow: SalesforceAuthFlow::AccessToken,
			login_url: Some(self.login_url.clone()),
			client_id: Some(self.client_id.clone()),
			client_secret: self.client_secret.clone(),
			username: None,
			private_key_pem: None,
			access_token: Some(token_response.access_token.clone()),
			refresh_token: token_response.refresh_token.clone(),
			instance_url: Some(instance_url.clone()),
		};

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

	fn token_url(&self) -> Result<TokenUrl, SalesforceAuthError> {
		let normalized = self.login_url.trim_end_matches('/');
		let url = format!("{normalized}/services/oauth2/token");

		Ok(TokenUrl::new(url.clone())
			.map_err(|source| SalesforceAuthError::InvalidUrl { url, source })?)
	}
}

async fn receive_oauth_callback(
	listener: TcpListener,
	callback_response: Option<&str>,
) -> Result<HashMap<String, String>, SalesforceAuthError> {
	let (mut stream, _) = listener.accept().await?;

	let mut buffer = vec![0_u8; 8192];
	let read = stream.read(&mut buffer).await?;
	let request = String::from_utf8_lossy(&buffer[..read]);

	let request_line = request
		.lines()
		.next()
		.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;

	let path = request_line
		.split_whitespace()
		.nth(1)
		.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;

	let callback_url = Url::parse(&format!("http://localhost{path}"))
		.map_err(|_| SalesforceAuthError::InvalidOAuthCallback)?;

	let params = callback_url
		.query_pairs()
		.map(|(key, value)| (key.to_string(), value.to_string()))
		.collect::<HashMap<_, _>>();

	let body = callback_response.unwrap_or(DEFAULT_CALLBACK_RESPONSE);
	let response = format!(
		concat!(
			"HTTP/1.1 200 OK\r\n",
			"Content-Type: text/html; charset=utf-8\r\n",
			"Content-Length: {}\r\n",
			"Connection: close\r\n",
			"\r\n",
			"{}"
		),
		body.len(),
		body
	);

	stream.write_all(response.as_bytes()).await?;
	stream.shutdown().await?;

	Ok(params)
}

fn create_state() -> String {
	let nanos = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|duration| duration.as_nanos())
		.unwrap_or_default();

	format!("rustsf-auth-{nanos}")
}