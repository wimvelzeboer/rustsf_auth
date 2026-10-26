use secrecy::{ExposeSecret, SecretString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::credentials::{http_client, required, SalesforceAuthFlow, SalesforceCredentials};
use crate::error::SalesforceAuthError;
use crate::salesforce_token_response::SalesforceTokenResponse;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use serde::Serialize;
use sha2::Sha256;
use time::OffsetDateTime;
use crate::salesforce_token_endpoint;

#[derive(Debug, Serialize)]
struct JwtHeader<'a> {
	alg: &'a str,
	typ: &'a str,
}

#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
	iss: &'a str,
	sub: &'a str,
	aud: &'a str,
	exp: i64,
}

impl SalesforceCredentials {
	/// Creates a configuration for the Salesforce JWT bearer flow.
	///
	/// The private key must be an RSA private key in PEM format. It should
	/// correspond to the certificate configured on the Salesforce connected app.
	///
	/// # Examples
	///
	/// ```rust
	/// use rustsf_auth::{SalesforceCredentials, SalesforceAuthFlow};
	///
	/// let config = SalesforceCredentials::jwt_bearer(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "user@example.com",
	///     "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
	/// );
	///
	/// assert_eq!(config.flow, SalesforceAuthFlow::JwtBearer);
	/// assert_eq!(config.username.as_deref(), Some("user@example.com"));
	/// ```
	pub fn jwt_bearer(
		login_url: impl Into<String>,
		client_id: impl Into<String>,
		username: impl Into<String>,
		private_key_pem: impl Into<String>,
	) -> Self {
		Self {
			flow: SalesforceAuthFlow::JwtBearer,
			login_url: Some(login_url.into()),
			client_id: Some(client_id.into()),
			client_secret: None,
			username: Some(username.into()),
			private_key_pem: Some(SecretString::new(Box::from(private_key_pem.into()))),
			access_token: None,
			refresh_token: None,
			instance_url: None,
		}
	}

	/// Authenticates to Salesforce using the JWT bearer flow.
	///
	/// This function creates a signed RS256 JWT assertion and exchanges it for a
	/// Salesforce access token.
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError`] if the private key cannot be parsed, the JWT
	/// cannot be signed, the token URL is invalid, the HTTP request fails, or
	/// Salesforce rejects the assertion.
	///
	/// # Examples
	///
	/// ```rust, ignore
	/// use rustsf_auth::authenticate_jwt_bearer;
	///
	/// # async fn example() -> Result<(), rustsf_auth::SalesforceAuthError> {
	/// let private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----";
	///
	/// let session = authenticate_jwt_bearer(
	///     "https://login.salesforce.com",
	///     "client-id",
	///     "user@example.com",
	///     private_key_pem,
	/// ).await?;
	///
	/// println!("{}", session.access_token);
	/// # Ok(())
	/// # }
	/// ```
	pub(crate) async fn connect_jwt(&self) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		let login_url = required(self.login_url.as_deref(), "login_url")?;
		let client_id = required(self.client_id.as_deref(), "client_id")?;
		let username = required(self.username.as_deref(), "username")?;
		let private_key_pem = required(self.private_key_pem.as_ref().map(|s| s.expose_secret()), "private_key_pem")?;

		let assertion = create_salesforce_jwt_assertion(login_url, client_id, username, private_key_pem)?;

		Ok(http_client()?
			.post(salesforce_token_endpoint(login_url.trim_end_matches('/')))
			.form(&[
				("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
				("assertion", assertion.as_str()),
			])
			.send()
			.await?
			.error_for_status()?
			.json::<SalesforceTokenResponse>()
			.await?)
	}

}



/// Creates a signed Salesforce JWT bearer assertion.
///
/// The returned string is a compact JWT signed with RS256. It is intended for
/// the Salesforce OAuth 2.0 JWT bearer grant.
///
/// # Errors
///
/// Returns [`SalesforceAuthError::Jwt`] if the private key cannot be parsed,
/// the JWT claims cannot be serialized, or signing fails.
pub fn create_salesforce_jwt_assertion(
	login_url: &str,
	client_id: &str,
	username: &str,
	private_key_pem: &str,
) -> Result<String, SalesforceAuthError> {
	let header = JwtHeader {
		alg: "RS256",
		typ: "JWT",
	};

	let claims = JwtClaims {
		iss: client_id,
		sub: username,
		aud: login_url.trim_end_matches('/'),
		exp: OffsetDateTime::now_utc().unix_timestamp() + 180,
	};

	let encoded_header = encode_json_base64_url(&header)?;
	let encoded_claims = encode_json_base64_url(&claims)?;
	let signing_input = format!("{encoded_header}.{encoded_claims}");

	let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
		.or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
		.map_err(|error| SalesforceAuthError::Jwt(error.to_string()))?;

	let signing_key = SigningKey::<Sha256>::new(private_key);
	let mut rng = rsa::rand_core::OsRng;
	let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
	let encoded_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

	Ok(format!("{signing_input}.{encoded_signature}"))
}

fn encode_json_base64_url<T: Serialize>(value: &T) -> Result<String, SalesforceAuthError> {
	let json = serde_json::to_vec(value).map_err(|error| SalesforceAuthError::Jwt(error.to_string()))?;
	Ok(URL_SAFE_NO_PAD.encode(json))
}