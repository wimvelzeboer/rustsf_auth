//! RustSF Authentication library - OAuth2.0 Web Server Flow Example
//!
//! In this example, we demonstrate how to use the RustSF Authentication library to authenticate
//! with a OAuth2.0 Web Server flow.
//! A flow where the user is redirected to Salesforce to authenticate,
//! and then redirected back to the application.
//! The library will listen to the redirect url (http://localhost:1717/OauthRedirect),
//! and then exchange the code for an access token.
//!
//! The user must have API access enabled to be able to make API calls to Salesforce.
//!
use std::process::Command;

use oauth2::http::header::AUTHORIZATION;
use oauth2::http::{HeaderMap, HeaderValue};
use rustsf_auth::OAuthWebService;

pub const CONNECT_TIMEOUT: u64 = 15;
pub const REQUEST_TIMEOUT: u64 = 30;

fn open_browser(url: &str) {
	#[cfg(target_os = "windows")]
	{
		let _ = Command::new("cmd")
			.args(["/C", "start", "", url])
			.spawn();
	}

	#[cfg(target_os = "macos")]
	{
		let _ = Command::new("open")
			.arg(url)
			.spawn();
	}

	#[cfg(all(unix, not(target_os = "macos")))]
	{
		let _ = Command::new("xdg-open")
			.arg(url)
			.spawn();
	}
}

#[tokio::main]
async fn main() {
	// The client id, urls and scopes.
	let login_url = "https://example.my.salesforce.com/";
	let client_id = "PlatformCLI"; // The connected app the SFDX CLI is using
	let client_secret = None;
	let scopes = None;
	let redirect_url = "http://localhost:1717/OauthRedirect";

	// Prepare the Web Service
	let web_service = OAuthWebService::new(
		login_url,
		client_id,
		client_secret,
		redirect_url,
		scopes,
	)
		// Optionally: add a custom callback response the user will see after authentication
		.with_callback_response(
			r#"<!doctype html>
<html>
	<head><title>Authenticated</title></head>
	<body>
		<h1>Authentication complete</h1>
		<p>You can close this tab.</p>
	</body>
</html>"#,
		);
	let auth_url = web_service.authorization_url().await.unwrap();

	// Ask user to authenticate themselves
	println!("Open this URL in your browser if it did not open automatically:\n{auth_url}");
	open_browser(&auth_url);
	let session = web_service.connect().await.unwrap();

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