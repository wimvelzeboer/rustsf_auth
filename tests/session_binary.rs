use httpmock::Method::POST;
use httpmock::MockServer;
use rustsf_auth::{SalesforceAuthSession, SalesforceCredentials};
use secrecy::ExposeSecret;
use serde_json::json;

#[tokio::test]
async fn public_binary_round_trip_restores_session_and_refresh_credentials() {
	let server = MockServer::start();
	let credentials = SalesforceCredentials::access_token(
		"credential-access-token",
		"https://instance.example.test",
		Some("refresh-token".to_string()),
		Some("client-id".to_string()),
		Some("client-secret".to_string()),
		Some(server.base_url()),
	);
	let session = credentials.connect().await.unwrap();

	let restored = SalesforceAuthSession::from_binary(&session.to_binary().unwrap()).unwrap();
	assert_eq!(restored.access_token().await.unwrap(), "credential-access-token");
	assert_eq!(
		restored.credentials.refresh_token.as_ref().unwrap().expose_secret(),
		"refresh-token"
	);
	assert_eq!(
		restored.credentials.client_secret.as_ref().unwrap().expose_secret(),
		"client-secret"
	);

	let refresh = server.mock(|when, then| {
		when.method(POST)
			.path("/services/oauth2/token")
			.body_contains("grant_type=refresh_token")
			.body_contains("client_id=client-id")
			.body_contains("refresh_token=refresh-token");

		then.status(200)
			.header("content-type", "application/json")
			.json_body(json!({
				"access_token": "refreshed-access-token",
				"token_type": "Bearer",
				"instance_url": "https://instance.example.test"
			}));
	});

	restored.refresh_access_token().await.unwrap();
	assert_eq!(restored.access_token().await.unwrap(), "refreshed-access-token");
	refresh.assert();
}
