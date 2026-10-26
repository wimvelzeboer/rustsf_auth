use crate::SalesforceAuthError;
use crate::credentials::{SalesforceAuthFlow, SalesforceCredentials, http_client, required};
use crate::salesforce_token_response::SalesforceTokenResponse;
use log::trace;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Struct used to deserialize the SFDX auth URL json file,
/// which can be created via:.
/// ```bash
/// sf org auth show-sfdx-auth-url --target-org $ORG-ALIAS --json > sfdx_auth_url.json
/// ```
#[derive(Deserialize, Serialize)]
pub struct SfdxAuthJson {
	pub status: String,
	pub result: SfdxAuthJsonResult,
	pub warnings: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SfdxAuthJsonResult {
	pub sfdx_auth_url: String,
}

impl SalesforceCredentials {
	/// Creates a configuration for authenticating from an SFDX auth URL.
	///
	/// The SFDX URL must match:
	///
	/// `force://CLIENT_ID:CLIENT_SECRET:REFRESH_TOKEN@LOGIN_ENDPOINT`
	///
	/// The login endpoint must not include `https://`.
	///
	/// # Examples
	///
	/// ```rust, ignore
	/// use rustsf_auth::{SalesforceCredentials, SalesforceAuthFlow};
	///
	/// let config = SalesforceCredentials::sfdx_url(
	///     "force://client_id:client_secret:refresh-token@login.salesforce.com",
	/// );
	///
	/// assert_eq!(config.flow, SalesforceAuthFlow::SfdxUrl);
	/// assert!(config.sfdx_url.is_some());
	/// ```
	pub fn sfdx_url(url: impl Into<String>) -> Result<Self, SalesforceAuthError> {
		let regex =
			Regex::new(r"force://([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]*):([a-zA-Z0-9._-]+={0,2})@([a-zA-Z0-9._-]+)")
				.unwrap();

		let url = url.into();

		let captures = regex
			.captures(&url)
			// .with_context(|| "Invalid Authentication URL expected 'force://([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]*):([a-zA-Z0-9._-]+={0,2})@([a-zA-Z0-9._-]+)'".to_string())?;
			.ok_or(SalesforceAuthError::InvalidSfdxUrl)?;

		let client_id = captures
			.get(1)
			.ok_or(SalesforceAuthError::InvalidSfdxUrl)?
			.as_str()
			.to_string();

		let client_secret = captures
			.get(2)
			.map(|capture| capture.as_str().to_string())
			.filter(|value| !value.is_empty());

		let refresh_token = captures
			.get(3)
			.ok_or(SalesforceAuthError::InvalidSfdxUrl)?
			.as_str()
			.to_string();

		let login_endpoint = captures.get(4).ok_or(SalesforceAuthError::InvalidSfdxUrl)?.as_str();

		Ok(Self {
			flow: SalesforceAuthFlow::SfdxUrl,
			login_url: Some(format!("https://{login_endpoint}")),
			client_id: Some(client_id),
			client_secret: match client_secret {
				None => None,
				Some(secret) => Some(SecretString::new(secret.into())),
			},
			username: None,
			private_key_pem: None,
			access_token: None,
			refresh_token: Some(SecretString::new(Box::from(refresh_token))),
			instance_url: None,
		})
	}

	/// Creates a configuration for authenticating from an SFDX auth URL.
	///
	/// # Example
	///
	/// Export the SFDX auth URL in a json via:
	/// ```bash
	/// sf org auth show-sfdx-auth-url --target-org $ORG-ALIAS --json > sfdx_auth_url.json
	/// ```
	/// Then use the generated json file in your application
	/// ```rust, ignore
	///  use rustsf_auth::{SalesforceCredentials, SfdxAuthJson};
	///
	///  let file = fs::File::open("sfdx_auth_url.json")?;
	///  let sfdx_auth_json: SfdxAuthJson = serde_json::from_reader(file)?;
	///  let session = config.connect().await.unwrap();
	/// ```
	pub fn sfdx_url_json(sfdx_auth_json: SfdxAuthJson) -> Result<Self, SalesforceAuthError> {
		SalesforceCredentials::sfdx_url(sfdx_auth_json.result.sfdx_auth_url)
	}

	/// Authenticates to Salesforce from an SFDX auth URL.
	///
	/// The SFDX URL must match:
	///
	/// `force://([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]*):([a-zA-Z0-9._-]+={0,2})@([a-zA-Z0-9._-]+)`
	///
	/// Regex groups are interpreted as:
	///
	/// 1. client ID
	/// 2. client secret
	/// 3. refresh token
	/// 4. login endpoint without `https://`
	///
	/// Internally this parses the SFDX URL and then calls [`refresh_access_token`].
	///
	/// # Errors
	///
	/// Returns [`SalesforceAuthError::InvalidSfdxUrl`] if the URL does not match
	/// the required format. Returns other [`SalesforceAuthError`] variants if the
	/// refresh request fails.
	///
	/// # Examples
	///
	/// ```rust,ignore
	/// use rustsf_auth::authenticate_sfdx_url;
	///
	/// # async fn example() -> Result<(), rustsf_auth::SalesforceAuthError> {
	/// let session = authenticate_sfdx_url(
	///     "force://client_id:client_secret:refresh-token@login.salesforce.com",
	/// ).await?;
	///
	/// println!("{}", session.access_token);
	/// # Ok(())
	/// # }
	/// ```
	pub(crate) async fn connect_sfdx_url(&self) -> Result<SalesforceTokenResponse, SalesforceAuthError> {
		let client_id = required(self.client_id.as_deref(), "client_id")?;
		let refresh_token = required(self.refresh_token.as_ref().map(|s| s.expose_secret()), "refresh_token")?;

		let url = self.token_url()?.url().clone();
		let data = &[
			("grant_type", "refresh_token"),
			("client_id", client_id),
			("refresh_token", refresh_token),
		];
		let response = http_client()?.post(url).form(data).send().await?;

		let status = response.status();
		let body = response.text().await.map_err(|e| SalesforceAuthError::Http(e))?;

		if !status.is_success() {
			return Err(SalesforceAuthError::OAuth2(body));
		}

		Ok(serde_json::from_str::<SalesforceTokenResponse>(&body)
			.map_err(|e| SalesforceAuthError::TokenExchange(e.to_string()))?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_sfdx_url_json_valid() {
		let sfdx_auth_json = SfdxAuthJson {
			status: "0".to_string(),
			result: SfdxAuthJsonResult {
				sfdx_auth_url: "force://my_client_id:my_client_secret:my_refresh_token@login.salesforce.com"
					.to_string(),
			},
			warnings: vec![],
		};

		let result = SalesforceCredentials::sfdx_url_json(sfdx_auth_json);

		assert!(result.is_ok());
		let credentials = result.unwrap();
		assert_eq!(credentials.flow, SalesforceAuthFlow::SfdxUrl);
		assert_eq!(credentials.client_id, Some("my_client_id".to_string()));
		assert_eq!(credentials.client_secret.unwrap().expose_secret(), "my_client_secret");
		assert_eq!(credentials.refresh_token.unwrap().expose_secret(), "my_refresh_token");
		assert_eq!(credentials.login_url, Some("https://login.salesforce.com".to_string()));
		assert!(credentials.username.is_none());
		assert!(credentials.private_key_pem.is_none());
		assert!(credentials.access_token.is_none());
		assert!(credentials.instance_url.is_none());
	}

	#[test]
	fn test_sfdx_url_valid_with_client_secret() {
		let url = "force://my_client_id:my_client_secret:my_refresh_token@login.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_ok());
		let credentials = result.unwrap();
		assert_eq!(credentials.flow, SalesforceAuthFlow::SfdxUrl);
		assert_eq!(credentials.client_id, Some("my_client_id".to_string()));
		assert_eq!(credentials.client_secret.unwrap().expose_secret(), "my_client_secret");
		assert_eq!(credentials.refresh_token.unwrap().expose_secret(), "my_refresh_token");
		assert_eq!(credentials.login_url, Some("https://login.salesforce.com".to_string()));
		assert!(credentials.username.is_none());
		assert!(credentials.private_key_pem.is_none());
		assert!(credentials.access_token.is_none());
		assert!(credentials.instance_url.is_none());
	}

	#[test]
	fn test_sfdx_url_valid_without_client_secret() {
		let url = "force://PlatformCLI::refresh_token_value@test.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_ok());
		let credentials = result.unwrap();
		assert_eq!(credentials.flow, SalesforceAuthFlow::SfdxUrl);
		assert_eq!(credentials.client_id, Some("PlatformCLI".to_string()));
		assert!(credentials.client_secret.is_none());
		assert_eq!(credentials.refresh_token.unwrap().expose_secret(), "refresh_token_value");
		assert_eq!(credentials.login_url, Some("https://test.salesforce.com".to_string()));
	}

	#[test]
	fn test_sfdx_url_with_base64_refresh_token() {
		let url = "force://client123:secret456:dGVzdF90b2tlbl92YWx1ZQ==@login.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_ok());
		let credentials = result.unwrap();
		assert_eq!(credentials.client_id, Some("client123".to_string()));
		assert_eq!(credentials.client_secret.unwrap().expose_secret(), "secret456");
		assert_eq!(credentials.refresh_token.unwrap().expose_secret(), "dGVzdF90b2tlbl92YWx1ZQ==");
	}

	#[test]
	fn test_sfdx_url_invalid_format() {
		let url = "https://invalid-format.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SalesforceAuthError::InvalidSfdxUrl));
	}

	#[test]
	fn test_sfdx_url_missing_components() {
		let url = "force://client_id:@login.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SalesforceAuthError::InvalidSfdxUrl));
	}

	#[test]
	fn test_sfdx_url_invalid_scheme() {
		let url = "http://client_id:secret:token@login.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SalesforceAuthError::InvalidSfdxUrl));
	}

	#[test]
	fn test_sfdx_url_with_special_characters() {
		let url = "force://client.id-123:secret_456:refresh-token.value@test-env.salesforce.com";
		let result = SalesforceCredentials::sfdx_url(url);

		assert!(result.is_ok());
		let credentials = result.unwrap();
		assert_eq!(credentials.client_id, Some("client.id-123".to_string()));
		assert_eq!(credentials.client_secret.unwrap().expose_secret(), "secret_456");
		assert_eq!(credentials.refresh_token.unwrap().expose_secret(), "refresh-token.value");
		assert_eq!(
			credentials.login_url,
			Some("https://test-env.salesforce.com".to_string())
		);
	}
}
