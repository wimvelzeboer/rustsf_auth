//! RustSF Authentication library - OAuth2.0 Client Credentials Example
//!
//! In this example, we demonstrate how to use the RustSF Authentication library to authenticate
//! with a client id and secret.
//! The example includes the necessary imports, constants, and a main function that performs the
//! authentication and makes a REST API request.
//!
//! The flow is using the login url, client id, and secret for authentication.
//! This requires creating an External Client App in Salesforce.
//! Follow these steps below to create one;
//!
//! - Login into Salesforce and goto "Setup"
//! - Goto "Apps" -> "App Manager"
//! - Click on "New App" -> "New External Client App" and populate the following fields":
//!     - External Client App Name: "MyApp"
//!     - API Name: "MyApp"
//!     - Contact Email: "you@example.com"
//! - Expand the "API (Enable OAuth Settings)" section, check the "Enable OAuth" checkbox,
//! and populate the following fields:
//!     - Callback URL: "http://localhost/"  (its actually not used)
//!     - Add "Manage user data APIs (api)" to the selected OAuth Scopes, (and any other you might need)
//! - Check the "Enable Client Credentials Flow" checkbox, in the "Flow Enablement" section
//! - Click on the "Create" button.
//! - In Setup goto "Apps" -> "External Client Apps" -> "External Client App Manager",
//! and click on the name of your newly created App, e.g. "MyApp"
//! - Goto the "Settings" tab, and expand the "OAuth Settings" section
//! - Click the "Customer Key and Secret" button, follow the instructions,
//! and copy the "Consumer Key" and "Consumer Secret" to a save location.
//! - Goto the "Policies" tab, and expand the "OAuth Policies" section.
//! - Check the checkbox "Enable Client Credentials Flow" and assign a user to the Connected App.
//!
use oauth2::http::header::AUTHORIZATION;
use oauth2::http::{HeaderMap, HeaderValue};
use rustsf_auth::credentials::SalesforceCredentials;

pub const CONNECT_TIMEOUT: u64 = 15;
pub const REQUEST_TIMEOUT: u64 = 30;
#[tokio::main]
async fn main(){
	// The client id and secret, (should never be hardcoded)
	let login_url = "https://example.my.salesforce.com/";
	let client_id = "client_id";
	let client_secret = "client_secret";

	// The Credentials configuration
	let config = SalesforceCredentials::client_credentials(
		login_url,
		client_id,
		client_secret);

	// Constructing the authentication session and connecting to Salesforce
	let session = config.connect().await.unwrap();

	// Build the headers to include the access token
	let mut headers = HeaderMap::new();
	let auth_value = format!("Bearer {}", session.access_token().await.unwrap());
	headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());

	// A REST API request
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