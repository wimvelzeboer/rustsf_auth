//! RustSF Authentication library - OAuth2.0 JWT Bearer Example
//!
//! In this example, we demonstrate how to use the RustSF Authentication library to authenticate
//! with a Salesforce connected app using the JWT bearer flow and make a REST API request.
//!
//! The JWT bearer flow uses an RSA private key to sign a JWT assertion. The matching certificate
//! must be uploaded to the Salesforce connected app. No client secret is required for this flow.
//!
//! Before running this example, create and configure a connected app in Salesforce:
//!
//! - Login into Salesforce and goto "Setup".
//! - Goto "Apps" -> "App Manager".
//! - Click on "New App" -> "New External Client App" and populate the following fields:
//!     - External Client App Name: "MyJwtApp"
//!     - API Name: "MyJwtApp"
//!     - Contact Email: "you@example.com"
//! - Expand the "API (Enable OAuth Settings)" section and enable OAuth.
//! - Add "Manage user data APIs (api)" to the selected OAuth scopes (and any other scopes you need).
//! - Enable "Use digital signatures" and upload the public certificate that matches your RSA private key.
//! - Create the app, then copy its "Consumer Key" from the "Settings" tab.
//! - In the connected app policies, permit the Salesforce user to use the app.
//!
//! Set the following environment variables before running the example:
//!
//! ```text
//! SALESFORCE_LOGIN_URL=https://login.salesforce.com
//! SALESFORCE_CLIENT_ID=your-connected-app-consumer-key
//! SALESFORCE_USERNAME=you@example.com
//! SALESFORCE_JWT_PRIVATE_KEY_PATH=/path/to/server.key
//! ```
//!
//! The private key file must contain an RSA private key in PEM format. The corresponding public
//! certificate must be configured in the connected app.

use std::env;
use std::fs;

use oauth2::http::header::AUTHORIZATION;
use oauth2::http::{HeaderMap, HeaderValue};
use rustsf_auth::credentials::SalesforceCredentials;

pub const CONNECT_TIMEOUT: u64 = 15;
pub const REQUEST_TIMEOUT: u64 = 30;

#[tokio::main]
async fn main() {
	let login_url = env::var("SALESFORCE_LOGIN_URL").unwrap_or_else(|_| "https://login.salesforce.com".to_string());
	let client_id = env::var("SALESFORCE_CLIENT_ID").expect("SALESFORCE_CLIENT_ID must be set");
	let username = env::var("SALESFORCE_USERNAME").expect("SALESFORCE_USERNAME must be set");
	let private_key_path =
		env::var("SALESFORCE_JWT_PRIVATE_KEY_PATH").expect("SALESFORCE_JWT_PRIVATE_KEY_PATH must be set");
	let private_key_pem = fs::read_to_string(private_key_path).expect("failed to read the Salesforce JWT private key");

	// The credentials configuration for the JWT bearer flow.
	let config = SalesforceCredentials::jwt_bearer(login_url, client_id, username, private_key_pem);

	// Construct the authentication session and connect to Salesforce.
	let session = config.connect().await.unwrap();

	// Build the headers to include the access token.
	let mut headers = HeaderMap::new();
	let auth_value = format!("Bearer {}", session.access_token().await.unwrap());
	headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());

	// A REST API request.
	let response = reqwest::Client::builder()
		.redirect(reqwest::redirect::Policy::none())
		.connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT))
		.timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT))
		.build()
		.unwrap()
		.get(format!("{}/services/data", session.instance_url))
		.headers(headers)
		.send()
		.await
		.unwrap();

	if response.status().is_success() {
		println!("SUCCESS Response: {:?}", response.text().await.unwrap());
	} else {
		println!("ERROR Response: {:?}", response.text().await.unwrap());
	}
}
