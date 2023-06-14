use anyhow::Result;
use jsonwebkey::{Algorithm as JWKAlgo, JsonWebKey};
use jsonwebtoken::{decode, decode_header, Algorithm as JWTAlgo, TokenData, Validation};
use serde::{Deserialize, Serialize};

use std::{collections::HashMap, fmt::Display};

use super::JwkConfiguration;

pub(crate) enum VerificationError {
    InvalidSignature,
    IncompleteKey,
    PublicKeyNotFound,
    UnknownKeyAlgorithm,
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidSignature => f.write_str("Invalid signature"),
            VerificationError::IncompleteKey => f.write_str("Incomplete JWT"),
            VerificationError::PublicKeyNotFound => f.write_str("Could not find matching pk"),
            VerificationError::UnknownKeyAlgorithm => f.write_str("Unknown key algorithm"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct JwkVerifier {
    keys: HashMap<String, JsonWebKey>,
    config: JwkConfiguration,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) sub: String, // Subject (UID)
    exp: usize,             // Expiration time (as UTC timestamp)
    aud: String,            // Audience
    iat: usize,             // Issued at (as UTC timestamp)
    iss: String,            // Issuer
}

fn keys_to_map(keys: Vec<JsonWebKey>) -> HashMap<String, JsonWebKey> {
    let mut keys_as_map = HashMap::new();
    for key in keys {
        if let Some(key_id) = &key.key_id {
            keys_as_map.insert(key_id.clone(), key.clone());
        }
    }
    keys_as_map
}

impl JwkVerifier {
    pub(crate) fn new(config: JwkConfiguration, keys: Vec<JsonWebKey>) -> JwkVerifier {
        JwkVerifier {
            keys: keys_to_map(keys),
            config,
        }
    }

    pub(crate) fn verify(&self, token: &str) -> Result<TokenData<Claims>, VerificationError> {
        let token_kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(header)) => header,
            _ => return Err(VerificationError::IncompleteKey),
        };
        let jwk_key = self
            .get_key(token_kid)
            .ok_or(VerificationError::PublicKeyNotFound)?;
        self.decode_token_with_key(&mut jwk_key.clone(), token)
    }

    fn get_key(&self, key_id: String) -> Option<&JsonWebKey> {
        self.keys.get(&key_id)
    }

    fn decode_token_with_key(
        &self,
        jwk: &mut JsonWebKey,
        token: &str,
    ) -> Result<TokenData<Claims>, VerificationError> {
        if jwk.algorithm != Some(JWKAlgo::RS256) {
            return Err(VerificationError::UnknownKeyAlgorithm);
        }
        jwk.set_algorithm(JWKAlgo::RS256)
            .map_err(|_| VerificationError::UnknownKeyAlgorithm)?;
        let algorithm: JWTAlgo = jwk.algorithm.unwrap().into();

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[self.config.issuer.clone()]);

        decode::<Claims>(token, &jwk.key.to_decoding_key(), &validation)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}
