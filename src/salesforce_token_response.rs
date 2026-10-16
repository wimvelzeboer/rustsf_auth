use serde::Deserialize;

/// Raw OAuth token response returned by Salesforce.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SalesforceTokenResponse {
	pub(crate) access_token: String,
	pub(crate) instance_url: Option<String>,
	pub(crate) id: Option<String>,
	pub(crate) token_type: Option<String>,
	pub(crate) issued_at: Option<String>,
	pub(crate) signature: Option<String>,
	pub(crate) refresh_token: Option<String>,
}

