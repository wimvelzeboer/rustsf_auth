//! RustSF Authentication library - OAuth2.0 SFDX Auth URL Example
//!
//! In this example, we demonstrate how to use the RustSF Authentication library to authenticate
//! with Salesforce using an SFDX auth URL.
//! The example includes the necessary imports, constants, and a main function that performs the
//! authentication and makes a REST API request.
//!
//! To create a SFDX Auth url, follow these steps:
//! - Download and install the SFDX CLI
//! - [Authenticate a Salesforce environment with the SFDX CLI](https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/cli_reference_org_login_web.html)
//! ```bash
//! sf org login web --alias my-org-alias
//! ```
//! - Export the SFDX Auth url from the CLI
//! ```bash
//! sf org auth show-sfdx-auth-url --target-org my-org-alias
//! ```
//! - Copy the sfdxAuthUrl and import it into your application in a save and secure manner,
//! and never hardcode it!  (like in the example below)
use oauth2::http::header::AUTHORIZATION;
use oauth2::http::{HeaderMap, HeaderValue};
use rustsf_auth::credentials::SalesforceCredentials;

pub const CONNECT_TIMEOUT: u64 = 15;
pub const REQUEST_TIMEOUT: u64 = 30;
#[tokio::main]
async fn main(){
	// The sfdx auth url, normally never hardcoded
	let sfdx_auth_url = "force://PlatformCLI::TOKEN@name.sandbox.my.salesforce.com";

	// The Credentials configuration
	let config = SalesforceCredentials::sfdx_url(sfdx_auth_url).unwrap();

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
		.headers(headers.clone())
		.send()
		.await
		.unwrap();

	if response.status().is_success() {
		println!("SUCCESS Response: {:?}", response.text().await.unwrap());
	} else {
		println!("ERROR Response: {:?}", response.text().await.unwrap());
	}
}