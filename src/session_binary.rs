use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

use crate::credentials::{SalesforceAuthFlow, SalesforceCredentials};
use crate::salesforce_auth_token::SalesforceAuthToken;
use crate::{SalesforceAuthError, SalesforceAuthSession};

const MAGIC: &[u8; 4] = b"SFAS";
const VERSION: u8 = 1;

#[derive(Serialize)]
struct SessionSnapshotRef<'a> {
	token: TokenSnapshotRef<'a>,
	credentials: CredentialsSnapshotRef<'a>,
	instance_url: &'a str,
	org_id: Option<&'a str>,
	user_id: Option<&'a str>,
}

#[derive(Serialize)]
struct TokenSnapshotRef<'a> {
	access_token: &'a str,
	issued_at: Option<&'a str>,
	token_type: Option<&'a str>,
	signature: Option<&'a str>,
}

#[derive(Serialize)]
struct CredentialsSnapshotRef<'a> {
	flow: BinaryAuthFlow,
	login_url: Option<&'a str>,
	client_id: Option<&'a str>,
	client_secret: Option<&'a str>,
	username: Option<&'a str>,
	private_key_pem: Option<&'a str>,
	access_token: Option<&'a str>,
	refresh_token: Option<&'a str>,
	instance_url: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
enum BinaryAuthFlow {
	ClientCredentials,
	JwtBearer,
	SfdxUrl,
	AccessToken,
}

#[derive(Deserialize)]
struct SessionSnapshot<'a> {
	#[serde(borrow)]
	token: TokenSnapshot<'a>,
	#[serde(borrow)]
	credentials: CredentialsSnapshot<'a>,
	#[serde(borrow)]
	instance_url: &'a str,
	#[serde(borrow)]
	org_id: Option<&'a str>,
	#[serde(borrow)]
	user_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct TokenSnapshot<'a> {
	#[serde(borrow)]
	access_token: &'a str,
	#[serde(borrow)]
	issued_at: Option<&'a str>,
	#[serde(borrow)]
	token_type: Option<&'a str>,
	#[serde(borrow)]
	signature: Option<&'a str>,
}

#[derive(Deserialize)]
struct CredentialsSnapshot<'a> {
	flow: BinaryAuthFlow,
	#[serde(borrow)]
	login_url: Option<&'a str>,
	#[serde(borrow)]
	client_id: Option<&'a str>,
	#[serde(borrow)]
	client_secret: Option<&'a str>,
	#[serde(borrow)]
	username: Option<&'a str>,
	#[serde(borrow)]
	private_key_pem: Option<&'a str>,
	#[serde(borrow)]
	access_token: Option<&'a str>,
	#[serde(borrow)]
	refresh_token: Option<&'a str>,
	#[serde(borrow)]
	instance_url: Option<&'a str>,
}

pub(super) fn to_binary(session: &SalesforceAuthSession) -> Result<Vec<u8>, SalesforceAuthError> {
	let token = session.token_read();
	let credentials = &session.credentials;
	let snapshot = SessionSnapshotRef {
		token: TokenSnapshotRef {
			access_token: &token.access_token,
			issued_at: token.issued_at.as_deref(),
			token_type: token.token_type.as_deref(),
			signature: token.signature.as_deref(),
		},
		credentials: CredentialsSnapshotRef {
			flow: credentials.flow.clone().into(),
			login_url: credentials.login_url.as_deref(),
			client_id: credentials.client_id.as_deref(),
			client_secret: credentials.client_secret.as_ref().map(|secret| secret.expose_secret()),
			username: credentials.username.as_deref(),
			private_key_pem: credentials
				.private_key_pem
				.as_ref()
				.map(|secret| secret.expose_secret()),
			access_token: credentials.access_token.as_ref().map(|secret| secret.expose_secret()),
			refresh_token: credentials.refresh_token.as_ref().map(|secret| secret.expose_secret()),
			instance_url: credentials.instance_url.as_deref(),
		},
		instance_url: &session.instance_url,
		org_id: session.org_id.as_deref(),
		user_id: session.user_id.as_deref(),
	};

	let payload = bincode_next::serde::encode_to_vec(&snapshot, bincode_next::config::legacy())
		.map_err(|error| SalesforceAuthError::SessionBinary(error.to_string()))?;

	let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
	bytes.extend_from_slice(MAGIC);
	bytes.push(VERSION);
	bytes.extend_from_slice(&payload);
	Ok(bytes)
}

pub(super) fn from_binary(bytes: &[u8]) -> Result<SalesforceAuthSession, SalesforceAuthError> {
	if bytes.len() < MAGIC.len() + 1 || !bytes.starts_with(MAGIC) {
		return Err(binary_error("invalid or truncated session binary header"));
	}
	if bytes[MAGIC.len()] != VERSION {
		return Err(binary_error("unsupported session binary version"));
	}

	let payload = &bytes[MAGIC.len() + 1..];
	let (snapshot, consumed): (SessionSnapshot<'_>, usize) =
		bincode_next::serde::borrow_decode_from_slice(payload, bincode_next::config::legacy())
			.map_err(|error| binary_error(&error.to_string()))?;
	if consumed != payload.len() {
		return Err(binary_error("trailing data in session binary"));
	}

	let credentials = snapshot.credentials;
	Ok(SalesforceAuthSession {
		token: RwLock::new(SalesforceAuthToken {
			access_token: snapshot.token.access_token.to_owned(),
			issued_at: snapshot.token.issued_at.map(str::to_owned),
			token_type: snapshot.token.token_type.map(str::to_owned),
			signature: snapshot.token.signature.map(str::to_owned),
		}),
		credentials: SalesforceCredentials {
			flow: credentials.flow.into(),
			login_url: credentials.login_url.map(str::to_owned),
			client_id: credentials.client_id.map(str::to_owned),
			client_secret: credentials.client_secret.map(secret_string),
			username: credentials.username.map(str::to_owned),
			private_key_pem: credentials.private_key_pem.map(secret_string),
			access_token: credentials.access_token.map(secret_string),
			refresh_token: credentials.refresh_token.map(secret_string),
			instance_url: credentials.instance_url.map(str::to_owned),
		},
		instance_url: snapshot.instance_url.to_owned(),
		org_id: snapshot.org_id.map(str::to_owned),
		user_id: snapshot.user_id.map(str::to_owned),
	})
}

fn secret_string(value: &str) -> SecretString {
	SecretString::new(value.to_owned().into())
}

fn binary_error(message: &str) -> SalesforceAuthError {
	SalesforceAuthError::SessionBinary(message.to_string())
}

impl From<SalesforceAuthFlow> for BinaryAuthFlow {
	fn from(flow: SalesforceAuthFlow) -> Self {
		match flow {
			SalesforceAuthFlow::ClientCredentials => Self::ClientCredentials,
			SalesforceAuthFlow::JwtBearer => Self::JwtBearer,
			SalesforceAuthFlow::SfdxUrl => Self::SfdxUrl,
			SalesforceAuthFlow::AccessToken => Self::AccessToken,
		}
	}
}

impl From<BinaryAuthFlow> for SalesforceAuthFlow {
	fn from(flow: BinaryAuthFlow) -> Self {
		match flow {
			BinaryAuthFlow::ClientCredentials => Self::ClientCredentials,
			BinaryAuthFlow::JwtBearer => Self::JwtBearer,
			BinaryAuthFlow::SfdxUrl => Self::SfdxUrl,
			BinaryAuthFlow::AccessToken => Self::AccessToken,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn session(flow: SalesforceAuthFlow, with_optionals: bool) -> SalesforceAuthSession {
		let credentials = SalesforceCredentials {
			flow,
			login_url: with_optionals.then(|| "https://login.example.test".to_string()),
			client_id: with_optionals.then(|| "client-id".to_string()),
			client_secret: with_optionals.then(|| secret_string("client-secret")),
			username: with_optionals.then(|| "user@example.test".to_string()),
			private_key_pem: with_optionals.then(|| secret_string("private-key")),
			access_token: with_optionals.then(|| secret_string("credential-token")),
			refresh_token: with_optionals.then(|| secret_string("refresh-token")),
			instance_url: with_optionals.then(|| "https://credentials.example.test".to_string()),
		};

		SalesforceAuthSession {
			token: RwLock::new(SalesforceAuthToken {
				access_token: "current-token".to_string(),
				issued_at: with_optionals.then(|| "1700000000000".to_string()),
				token_type: with_optionals.then(|| "Bearer".to_string()),
				signature: with_optionals.then(|| "signature".to_string()),
			}),
			credentials,
			instance_url: "https://session.example.test".to_string(),
			org_id: with_optionals.then(|| "org-id".to_string()),
			user_id: with_optionals.then(|| "user-id".to_string()),
		}
	}

	fn assert_equal_state(left: &SalesforceAuthSession, right: &SalesforceAuthSession) {
		assert_eq!(left.token(), right.token());
		assert_eq!(left.credentials.flow, right.credentials.flow);
		assert_eq!(left.credentials.login_url, right.credentials.login_url);
		assert_eq!(left.credentials.client_id, right.credentials.client_id);
		assert_eq!(left.credentials.username, right.credentials.username);
		assert_eq!(left.credentials.instance_url, right.credentials.instance_url);
		assert_eq!(left.instance_url, right.instance_url);
		assert_eq!(left.org_id, right.org_id);
		assert_eq!(left.user_id, right.user_id);
		assert_eq!(
			left_secret(&left.credentials.client_secret),
			left_secret(&right.credentials.client_secret)
		);
		assert_eq!(
			left_secret(&left.credentials.private_key_pem),
			left_secret(&right.credentials.private_key_pem)
		);
		assert_eq!(
			left_secret(&left.credentials.access_token),
			left_secret(&right.credentials.access_token)
		);
		assert_eq!(
			left_secret(&left.credentials.refresh_token),
			left_secret(&right.credentials.refresh_token)
		);
	}

	fn left_secret(value: &Option<SecretString>) -> Option<&str> {
		value.as_ref().map(|secret| secret.expose_secret())
	}

	fn append_string(bytes: &mut Vec<u8>, value: &str) {
		bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
		bytes.extend_from_slice(value.as_bytes());
	}

	fn append_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) {
		if let Some(value) = value {
			bytes.push(1);
			append_string(bytes, value);
		} else {
			bytes.push(0);
		}
	}

	fn legacy_fixture(flow: u32, with_optionals: bool) -> Vec<u8> {
		let mut bytes = MAGIC.to_vec();
		bytes.push(VERSION);

		append_string(&mut bytes, "current-token");
		append_optional_string(&mut bytes, with_optionals.then_some("1700000000000"));
		append_optional_string(&mut bytes, with_optionals.then_some("Bearer"));
		append_optional_string(&mut bytes, with_optionals.then_some("signature"));

		bytes.extend_from_slice(&flow.to_le_bytes());
		append_optional_string(&mut bytes, with_optionals.then_some("https://login.example.test"));
		append_optional_string(&mut bytes, with_optionals.then_some("client-id"));
		append_optional_string(&mut bytes, with_optionals.then_some("client-secret"));
		append_optional_string(&mut bytes, with_optionals.then_some("user@example.test"));
		append_optional_string(&mut bytes, with_optionals.then_some("private-key"));
		append_optional_string(&mut bytes, with_optionals.then_some("credential-token"));
		append_optional_string(&mut bytes, with_optionals.then_some("refresh-token"));
		append_optional_string(&mut bytes, with_optionals.then_some("https://credentials.example.test"));

		append_string(&mut bytes, "https://session.example.test");
		append_optional_string(&mut bytes, with_optionals.then_some("org-id"));
		append_optional_string(&mut bytes, with_optionals.then_some("user-id"));
		bytes
	}

	#[test]
	fn preserves_bincode_1_legacy_format_for_all_flows_and_optionals() {
		for (flow, flow_tag) in [
			(SalesforceAuthFlow::ClientCredentials, 0),
			(SalesforceAuthFlow::JwtBearer, 1),
			(SalesforceAuthFlow::SfdxUrl, 2),
			(SalesforceAuthFlow::AccessToken, 3),
		] {
			for with_optionals in [false, true] {
				let original = session(flow.clone(), with_optionals);
				let expected = legacy_fixture(flow_tag, with_optionals);

				assert_eq!(original.to_binary().unwrap(), expected);
				let restored = SalesforceAuthSession::from_binary(&expected).unwrap();
				assert_equal_state(&original, &restored);
			}
		}
	}

	#[test]
	fn round_trip_preserves_all_flows_and_secret_values() {
		for flow in [
			SalesforceAuthFlow::ClientCredentials,
			SalesforceAuthFlow::JwtBearer,
			SalesforceAuthFlow::SfdxUrl,
			SalesforceAuthFlow::AccessToken,
		] {
			let original = session(flow, true);
			let restored = SalesforceAuthSession::from_binary(&original.to_binary().unwrap()).unwrap();

			assert_equal_state(&original, &restored);
			assert_eq!(restored.token().access_token, "current-token");
			assert_eq!(
				left_secret(&restored.credentials.access_token),
				Some("credential-token")
			);
		}
	}

	#[test]
	fn round_trip_preserves_absent_optional_values() {
		let original = session(SalesforceAuthFlow::AccessToken, false);
		let restored = SalesforceAuthSession::from_binary(&original.to_binary().unwrap()).unwrap();

		assert_equal_state(&original, &restored);
	}

	#[test]
	fn restored_token_lock_is_independent() {
		let original = session(SalesforceAuthFlow::AccessToken, true);
		let restored = SalesforceAuthSession::from_binary(&original.to_binary().unwrap()).unwrap();

		restored.token_write().access_token = "changed-restored-token".to_string();
		assert_eq!(original.token().access_token, "current-token");
		assert_eq!(restored.token().access_token, "changed-restored-token");
	}

	#[test]
	fn rejects_invalid_truncated_and_trailing_binary_data() {
		let original = session(SalesforceAuthFlow::AccessToken, true);
		let bytes = original.to_binary().unwrap();

		assert!(SalesforceAuthSession::from_binary(b"not a session").is_err());
		assert!(SalesforceAuthSession::from_binary(&bytes[..bytes.len() - 1]).is_err());
		let mut trailing = bytes;
		trailing.push(0);
		assert!(SalesforceAuthSession::from_binary(&trailing).is_err());
	}

	#[test]
	fn rejects_oversized_string_lengths_and_invalid_flow_tags() {
		let original = session(SalesforceAuthFlow::AccessToken, false);
		let mut oversized = original.to_binary().unwrap();
		let first_string_length = MAGIC.len() + 1;
		oversized[first_string_length..first_string_length + 8].copy_from_slice(&u64::MAX.to_le_bytes());
		assert!(SalesforceAuthSession::from_binary(&oversized).is_err());

		let mut invalid_flow = original.to_binary().unwrap();
		let flow_tag_offset = MAGIC.len() + 1 + 8 + "current-token".len() + 3 * 4;
		invalid_flow[flow_tag_offset..flow_tag_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
		assert!(SalesforceAuthSession::from_binary(&invalid_flow).is_err());
	}

	#[test]
	fn rejects_unsupported_version() {
		let original = session(SalesforceAuthFlow::AccessToken, false);
		let mut bytes = original.to_binary().unwrap();
		bytes[MAGIC.len()] = VERSION + 1;

		assert!(SalesforceAuthSession::from_binary(&bytes).is_err());
	}
}
