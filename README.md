[![crate-name at crates.io](https://img.shields.io/crates/v/rustsf_auth.svg)](https://crates.io/crates/rustsf)
[![crate-name at docs.rs](https://docs.rs/rustsf_auth/badge.svg)](https://docs.rs/rustsf_auth)

## RustSF Auth

Salesforce authentication SDK for Rust, supporting the OAuth2.0 flows:

- [Client Credentials](#client-credentials)
- JWT, 
- [sfdxAuthUrl](#sfdx-authentication-url), 
- [Web Server](#oauth-web-server-flow),
  (this flow waits for user interaction in a browser)

## Examples

### Client Credentials
The flow is using the login url, client id, and secret for authentication. 
This requires creating an [External Client App](https://trailhead.salesforce.com/content/learn/projects/create-an-external-client-app-using-metadata-api/create-an-external-client-app) in Salesforce.
```rust
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
```

### SFDX Authentication URL
Export the SFDX authentication URL using the [SFDX CLI](https://developer.salesforce.com/docs/atlas.en-us.sfdx_setup.meta/sfdx_setup/sfdx_setup_install_cli.htm), via the following command
```bash
sf org auth show-sfdx-auth-url --target-org my-org-alias --json > sfdx_auth_url.json
```
Use the exported SFDX authentication URL to authenticate with Salesforce using the `SalesforceCredentials::sfdx_url_json` method.
```rust
use oauth2::http::header::AUTHORIZATION;
use oauth2::http::{HeaderMap, HeaderValue};
use rustsf_auth::{SalesforceCredentials, SfdxAuthJson};
use std::fs;

pub const CONNECT_TIMEOUT: u64 = 15;
pub const REQUEST_TIMEOUT: u64 = 30;
#[tokio::main]
async fn main(){
	
	// Load the sfdx auth url
	let file = fs::File::open("my-org-alias.json")?;
	let sfdx_auth_json: SfdxAuthJson = serde_json::from_reader(file)?;
	
	// The Credentials configuration
	let config = SalesforceCredentials::sfdx_url_json(sfdx_auth_json).unwrap();

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
```

Alternatively you could enter the sfdxAuthUrl directly as a string via:
```rust
let config = SalesforceCredentials::sfdx_url("force://PlatformCLI::4sdf2348kS0Qqf3GEL....@example.my.salesforce.com").unwrap();
let session = config.connect().await.unwrap();
```


### OAuth Web Server Flow
With This authorization flow, users can authenticate themselves using a browser. 
The callback url is then invoked by Salesforce that sends a code with which the access_token and refresh token can be requested.

<<<<<<<<<<<<<<<<<<<<<<<<< Continue HERE