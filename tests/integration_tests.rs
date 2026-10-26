use std::env;
use log::LevelFilter;
use rustsf_auth::{SalesforceAuthFlow, SalesforceCredentials, SfdxAuthJson};

#[tokio::test]
#[ignore = "requires a valid SFDX_AUTH_URL and a Salesforce network connection"]
async fn test_sfdx_auth_json_methods() {

	env_logger::builder()
		.filter_level(LevelFilter::Trace)
		.format_target(false)
		.init();


	let sfdx_auth_url = env::var("SFDX_AUTH_URL")
		.expect("SFDX_AUTH_URL must contain a valid Salesforce SFDX auth URL");

	let credentials = SalesforceCredentials::sfdx_url(sfdx_auth_url.clone())
		.expect("SFDX_AUTH_URL should produce valid Salesforce credentials");
	assert_eq!(credentials.flow, SalesforceAuthFlow::SfdxUrl);

	let sfdx_auth_json: SfdxAuthJson = serde_json::from_value(serde_json::json!({
		"status": "0",
		"result": { "sfdxAuthUrl": sfdx_auth_url },
		"warnings": []
	}))
	.expect("the SFDX auth URL JSON should be valid");
	let json_credentials = SalesforceCredentials::sfdx_url_json(sfdx_auth_json)
	.expect("the SFDX auth URL JSON should produce valid Salesforce credentials");
	assert_eq!(json_credentials.flow, SalesforceAuthFlow::SfdxUrl);

	let session = credentials
		.connect()
		.await
		.expect("Salesforce should accept the SFDX auth URL");
	assert!(!session
		.access_token()
		.await
		.expect("an access token should be returned")
		.is_empty());
}