use crate::salesforce_token_response::SalesforceTokenResponse;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct SalesforceAuthToken {
	pub(crate) access_token: String,

	/// Token issue timestamp, when returned by Salesforce.
	pub(crate) issued_at: Option<String>,

	/// OAuth token type, usually `Bearer`.
	pub(crate) token_type: Option<String>,

	/// Salesforce response signature, when returned by Salesforce.
	pub(crate) signature: Option<String>,
}

impl SalesforceAuthToken {
	pub fn from_token_response(token_response: SalesforceTokenResponse) -> Self {
		Self {
			access_token: token_response.access_token,
			issued_at: token_response.issued_at,
			token_type: token_response.token_type,
			signature: token_response.signature,
		}
	}
	
	pub(crate) fn access_token(&self) -> String {
		self.access_token.clone()
	}

	pub fn is_expired(&self) -> bool {
		match &self.issued_at {
			Some(issued_at) => {
				let timestamp_ms = match issued_at.parse::<u64>() {
					Ok(ts) => ts,
					Err(_) => {
						// SOAP login returns ISO timestamp; can't compare, attempt refresh						
						return true;
					}
				};
				let seconds = timestamp_ms / 1000;
				let nanos = (timestamp_ms % 1000) * 1_000_000;

				let given_time = UNIX_EPOCH + Duration::new(seconds, nanos as u32);

				let two_hours = Duration::from_secs(2 * 60 * 60); // 2 hours in seconds
				let modified_time = given_time + two_hours;

				let current_time = SystemTime::now();

				if current_time > modified_time { true } else { false }		
			}
			None => false, // Assume token is valid, e.g., with the access_token authentication flow
		}		
	}
}