use anyhow::Result;
use jsonwebkey::JsonWebKey;
use serde::Deserialize;
use std::time::Duration;

use super::{get_max_age::get_max_age, JwkConfiguration};

#[derive(Debug)]
pub(crate) struct JsonWebKeys {
    pub(crate) keys: Vec<JsonWebKey>,
    pub(crate) validity: Duration,
}

#[derive(Deserialize)]
struct JwkResponse {
    pub(crate) keys: Vec<JsonWebKey>,
}

const FALLBACK_DURATION: Duration = Duration::from_secs(60);

pub(crate) async fn fetch_keys(config: &JwkConfiguration) -> Result<JsonWebKeys> {
    let raw_res = reqwest::get(config.jwk_url.to_owned()).await?;
    let validity = get_max_age(&raw_res).unwrap_or(FALLBACK_DURATION);
    let res: JwkResponse = raw_res.json().await?;
    Ok(JsonWebKeys {
        keys: res.keys,
        validity,
    })
}

#[tokio::test]
async fn fetches_keys_from_firebase_jwk() {
    let config = JwkConfiguration{
        jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
        audience: "my-firebase-app-12345".to_string(),
        issuer: "https://securetoken.google.com/my-firebase-app-12345".to_string(),
    };
    let res = fetch_keys(&config).await;
    assert!(res.is_ok());
    assert!(!res.unwrap().keys.is_empty())
}
