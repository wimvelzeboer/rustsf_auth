use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

use log::trace;
use oauth2::{CsrfToken, TokenUrl};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::credentials::{SalesforceAuthFlow, SalesforceCredentials, http_client, parse_salesforce_identity_ids};
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
#[derive(Clone)]
pub struct OAuthWebService {
	login_url: String,
	client_id: String,
	client_secret: Option<String>,
	redirect_uri: String,
	scopes: Vec<String>,
	pending_state: Arc<Mutex<Option<String>>>,
	callback_response: Option<String>,
}

impl fmt::Debug for OAuthWebService {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("OAuthWebService")
			.field("login_url", &self.login_url)
			.field("client_id", &self.client_id)
			.field("client_secret", &self.client_secret.as_ref().map(|_| "[REDACTED]"))
			.field("redirect_uri", &self.redirect_uri)
			.field("scopes", &self.scopes)
			.field("pending_state", &"[REDACTED]")
			.field("callback_response", &self.callback_response)
			.finish()
	}
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
			pending_state: Arc::new(Mutex::new(None)),
			callback_response: None,
		}
	}

	/// Builds the Salesforce authorization URL.
	///
	/// This method does not open a browser. The caller is responsible for opening
	/// the returned URL or presenting it to the user. Each call creates a new
	/// one-use state value and invalidates any authorization URL returned earlier
	/// by this helper or one of its clones.
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

		let mut url = Url::parse(&authorize_url).map_err(|source| SalesforceAuthError::InvalidUrl {
			url: authorize_url,
			source,
		})?;

		let state = CsrfToken::new_random().secret().to_string();
		let mut pending_state = self
			.pending_state
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		*pending_state = Some(state.clone());

		url.query_pairs_mut()
			.append_pair("response_type", "code")
			.append_pair("client_id", &self.client_id)
			.append_pair("redirect_uri", &self.redirect_uri)
			.append_pair("scope", &self.scopes.join(" "))
			.append_pair("state", &state)
			.append_pair("prompt", "login");
		drop(pending_state);

		Ok(url.to_string())
	}

	/// Starts listening for the OAuth callback and exchanges the authorization
	/// code for a Salesforce authentication session.
	///
	/// Call [`OAuthWebService::authorization_url`] first and open that URL in a
	/// browser before awaiting this method. Each authorization URL is a one-use
	/// attempt shared by clones of this helper; calling this method consumes it,
	/// including when the callback or token exchange fails. Generate a new URL
	/// before retrying.
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
	/// - No unconsumed authorization URL has been generated
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
		let expected_state = self
			.pending_state
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.take()
			.ok_or(SalesforceAuthError::MissingAuthorizationUrl)?;

		let callback_url = Url::parse(&self.redirect_uri).map_err(|source| SalesforceAuthError::InvalidUrl {
			url: self.redirect_uri.clone(),
			source,
		})?;

		let host = callback_url.host_str().unwrap_or("127.0.0.1");
		let port = callback_url
			.port_or_known_default()
			.ok_or(SalesforceAuthError::MissingRequiredField("redirect_uri port"))?;

		let bind_host = if host == "localhost" { "127.0.0.1" } else { host };
		let listener = TcpListener::bind((bind_host, port)).await?;

		let code = receive_oauth_callback(
			listener,
			callback_url.path(),
			&expected_state,
			self.callback_response.as_deref(),
		)
		.await?;

		let token_response = self.exchange_authorization_code(&code).await?;

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

	async fn exchange_authorization_code(&self, code: &str) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
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

		let response = http_client()?.post(url).form(&data).send().await?;

		let status = response.status();
		let body = response.text().await.map_err(SalesforceAuthError::Http)?;

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
			client_secret: match &self.client_secret {
				Some( client_secret) => Some(SecretString::new(Box::from(client_secret.clone()))),
				None => None,
			},
			username: None,
			private_key_pem: None,
			access_token: Some(SecretString::new(Box::from(token_response.access_token.clone()))),
			refresh_token: match token_response.refresh_token {
				Some(ref refresh_token) => Some(SecretString::new(Box::from(refresh_token.clone()))),
				None => None,
			},
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

		Ok(TokenUrl::new(url.clone()).map_err(|source| SalesforceAuthError::InvalidUrl { url, source })?)
	}
}

const MAX_CALLBACK_REQUEST_BYTES: usize = 8192;
const INVALID_CALLBACK_RESPONSE: &str = "Invalid OAuth callback.";

async fn receive_oauth_callback(
	listener: TcpListener,
	callback_path: &str,
	expected_state: &str,
	callback_response: Option<&str>,
) -> Result<String, SalesforceAuthError> {
	let (mut stream, _) = listener.accept().await?;
	let mut request = Vec::with_capacity(MAX_CALLBACK_REQUEST_BYTES);
	let mut buffer = [0_u8; 1024];

	while !request.windows(4).any(|window| window == b"\r\n\r\n") {
		if request.len() == MAX_CALLBACK_REQUEST_BYTES {
			send_callback_response(&mut stream, "400 Bad Request", INVALID_CALLBACK_RESPONSE).await?;
			return Err(SalesforceAuthError::InvalidOAuthCallback);
		}

		let read_limit = (MAX_CALLBACK_REQUEST_BYTES - request.len()).min(buffer.len());
		let read = stream.read(&mut buffer[..read_limit]).await?;
		if read == 0 {
			send_callback_response(&mut stream, "400 Bad Request", INVALID_CALLBACK_RESPONSE).await?;
			return Err(SalesforceAuthError::InvalidOAuthCallback);
		}
		request.extend_from_slice(&buffer[..read]);
	}

	let callback = parse_oauth_callback(&request, callback_path, expected_state);
	match callback {
		Ok(code) => {
			let body = callback_response.unwrap_or(DEFAULT_CALLBACK_RESPONSE);
			send_callback_response(&mut stream, "200 OK", body).await?;
			Ok(code)
		}
		Err(error) => {
			send_callback_response(&mut stream, "400 Bad Request", INVALID_CALLBACK_RESPONSE).await?;
			Err(error)
		}
	}
}

fn parse_oauth_callback(
	request: &[u8],
	callback_path: &str,
	expected_state: &str,
) -> Result<String, SalesforceAuthError> {
	let request = std::str::from_utf8(request).map_err(|_| SalesforceAuthError::InvalidOAuthCallback)?;
	let request_line = request
		.split("\r\n")
		.next()
		.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;
	let mut request_parts = request_line.split(' ');
	let method = request_parts.next();
	let target = request_parts.next();
	let version = request_parts.next();
	if method != Some("GET") || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) || request_parts.next().is_some() {
		return Err(SalesforceAuthError::InvalidOAuthCallback);
	}

	let target = target.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;
	if !target.starts_with('/') || target.starts_with("//") || target.contains('#') {
		return Err(SalesforceAuthError::InvalidOAuthCallback);
	}

	let callback_url =
		Url::parse(&format!("http://localhost{target}")).map_err(|_| SalesforceAuthError::InvalidOAuthCallback)?;
	if callback_url.path() != callback_path {
		return Err(SalesforceAuthError::InvalidOAuthCallback);
	}

	let mut state = None;
	let mut code = None;
	for (key, value) in callback_url.query_pairs() {
		match key.as_ref() {
			"state" => {
				if state.replace(value.into_owned()).is_some() {
					return Err(SalesforceAuthError::InvalidOAuthCallback);
				}
			}
			"code" => {
				if code.replace(value.into_owned()).is_some() {
					return Err(SalesforceAuthError::InvalidOAuthCallback);
				}
			}
			_ => {}
		}
	}

	let state = state
		.filter(|state| !state.is_empty())
		.ok_or(SalesforceAuthError::InvalidOAuthCallback)?;
	if state != expected_state {
		return Err(SalesforceAuthError::OAuthStateMismatch);
	}

	code.filter(|code| !code.is_empty())
		.ok_or(SalesforceAuthError::InvalidOAuthCallback)
}

async fn send_callback_response(
	stream: &mut tokio::net::TcpStream,
	status: &str,
	body: &str,
) -> Result<(), SalesforceAuthError> {
	let response = format!(
		"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	);
	stream.write_all(response.as_bytes()).await?;
	stream.shutdown().await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use httpmock::{Method::POST, MockServer};
	use std::net::{SocketAddr, TcpListener as StdTcpListener};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpStream;

	fn state_from_url(url: &str) -> String {
		Url::parse(url)
			.unwrap()
			.query_pairs()
			.find(|(key, _)| key == "state")
			.map(|(_, value)| value.into_owned())
			.unwrap()
	}

	#[tokio::test]
	async fn authorization_urls_use_fresh_state() {
		let service = OAuthWebService::new(
			"https://login.salesforce.com",
			"client-id",
			Some("client-secret".to_string()),
			"http://127.0.0.1:8080/callback",
			None,
		);

		let first_state = state_from_url(&service.authorization_url().await.unwrap());
		let second_state = state_from_url(&service.authorization_url().await.unwrap());

		assert_ne!(first_state, second_state);
		let debug = format!("{service:?}");
		assert!(!debug.contains("client-secret"));
		assert!(!debug.contains(&second_state));
	}

	#[tokio::test]
	async fn authorization_attempt_is_rotated_and_shared_across_clones() {
		let service = OAuthWebService::new(
			"https://login.salesforce.com",
			"client-id",
			None,
			"not a valid URL",
			None,
		);
		let clone = service.clone();

		let first_state = state_from_url(&service.authorization_url().await.unwrap());
		let second_state = state_from_url(&clone.authorization_url().await.unwrap());
		assert_ne!(first_state, second_state);

		assert!(matches!(
			service.connect().await,
			Err(SalesforceAuthError::InvalidUrl { .. })
		));
		assert!(matches!(
			clone.connect().await,
			Err(SalesforceAuthError::MissingAuthorizationUrl)
		));
	}

	#[tokio::test]
	async fn callback_from_superseded_authorization_url_is_rejected() {
		let token_server = MockServer::start();
		let token_mock = token_server.mock(|when, then| {
			when.method(POST).path("/services/oauth2/token");
			then.status(500);
		});
		let (service, address) = service_with_ephemeral_callback(&token_server.base_url());
		let first_state = state_from_url(&service.authorization_url().await.unwrap());
		let clone = service.clone();
		service.authorization_url().await.unwrap();

		let connect = tokio::spawn(async move { service.connect().await });
		let request = format!("GET /callback?code=auth-code&state={first_state} HTTP/1.1\r\nHost: localhost\r\n\r\n");
		let response = send_callback_request(address, &[request.as_bytes()]).await;

		assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
		assert!(matches!(
			connect.await.unwrap(),
			Err(SalesforceAuthError::OAuthStateMismatch)
		));
		assert!(matches!(
			clone.connect().await,
			Err(SalesforceAuthError::MissingAuthorizationUrl)
		));
		token_mock.assert_hits(0);
	}

	#[tokio::test]
	async fn valid_fragmented_callback_exchanges_code() {
		let token_server = MockServer::start();
		let token_mock = token_server.mock(|when, then| {
			when.method(POST)
				.path("/services/oauth2/token")
				.body_contains("grant_type=authorization_code")
				.body_contains("code=auth-code");
			then.status(200)
				.header("content-type", "application/json")
				.json_body(serde_json::json!({
					"access_token": "access-token",
					"instance_url": "https://example.salesforce.com",
					"token_type": "Bearer"
				}));
		});
		let (service, address) = service_with_ephemeral_callback(&token_server.base_url());
		let state = state_from_url(&service.authorization_url().await.unwrap());
		let connect = tokio::spawn(async move { service.connect().await });
		let request = format!("GET /callback?code=auth-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n");
		let split = request.len() / 2;
		let chunks = [request[..split].as_bytes(), request[split..].as_bytes()];
		let response = send_callback_request(address, &chunks).await;

		assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
		let session = connect.await.unwrap().unwrap();
		assert_eq!(session.access_token().await.unwrap(), "access-token");
		token_mock.assert();
	}

	#[tokio::test]
	async fn invalid_callbacks_are_rejected_without_token_exchange() {
		let token_server = MockServer::start();
		let token_mock = token_server.mock(|when, then| {
			when.method(POST).path("/services/oauth2/token");
			then.status(500);
		});

		for (method, target, expected_error) in [
			("GET", "/callback?code=auth-code", false),
			("GET", "/callback?state=wrong&code=auth-code", true),
			("GET", "/callback?state={state}&state=again&code=auth-code", false),
			("GET", "/callback?state={state}&code=one&code=two", false),
			("GET", "/wrong?state={state}&code=auth-code", false),
			("POST", "/callback?state={state}&code=auth-code", false),
		] {
			let (service, address) = service_with_ephemeral_callback(&token_server.base_url());
			let state = state_from_url(&service.authorization_url().await.unwrap());
			let target = target.replace("{state}", &state);
			let connect = tokio::spawn(async move { service.connect().await });
			let request = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
			let response = send_callback_request(address, &[request.as_bytes()]).await;
			assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

			let result = connect.await.unwrap();
			if expected_error {
				assert!(matches!(result, Err(SalesforceAuthError::OAuthStateMismatch)));
			} else {
				assert!(matches!(result, Err(SalesforceAuthError::InvalidOAuthCallback)));
			}
		}

		token_mock.assert_hits(0);
	}

	fn service_with_ephemeral_callback(login_url: &str) -> (OAuthWebService, SocketAddr) {
		let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		drop(listener);
		let redirect_uri = format!("http://{address}/callback");
		(
			OAuthWebService::new(login_url, "client-id", None, redirect_uri, None),
			address,
		)
	}

	async fn send_callback_request(address: SocketAddr, chunks: &[&[u8]]) -> String {
		let mut stream = None;
		for _ in 0..1000 {
			if let Ok(connected_stream) = TcpStream::connect(address).await {
				stream = Some(connected_stream);
				break;
			}
			tokio::task::yield_now().await;
		}
		let mut stream = stream.expect("OAuth callback listener did not accept connections");
		for chunk in chunks {
			stream.write_all(chunk).await.unwrap();
			tokio::task::yield_now().await;
		}
		let mut response = Vec::new();
		stream.read_to_end(&mut response).await.unwrap();
		String::from_utf8_lossy(&response).into_owned()
	}
}
