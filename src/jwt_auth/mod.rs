use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::{subgraph, supergraph};
use apollo_router::{graphql, register_plugin, Context};
use async_trait::async_trait;
use http::header::AUTHORIZATION;
use http::{HeaderValue, StatusCode};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;
use tower::{BoxError, ServiceBuilder, ServiceExt};

use self::fetch_keys::{fetch_keys, JsonWebKeys};
use self::public_operations::PublicOperationsValidator;
use self::verifier::{Claims, JwkVerifier};

mod fetch_keys;
mod get_max_age;
mod public_operations;
mod verifier;

#[derive(Debug, Default, Deserialize, JsonSchema, Clone)]
pub(crate) struct JwkConfiguration {
    pub(crate) jwk_url: String,
    pub(crate) audience: String,
    pub(crate) issuer: String,
}

#[derive(Clone, Default)]
struct JwtAuth {
    config: JwkConfiguration,
    jwk_cache: Arc<Mutex<Option<JsonWebKeys>>>,
    public_validator: PublicOperationsValidator,
}

impl JwtAuth {
    fn start_key_update(&mut self) {
        let config = self.config.clone();
        let cache_ref = self.jwk_cache.clone();
        tokio::task::spawn(async move {
            loop {
                let duration = match fetch_keys(&config).await {
                    Ok(jwk) => {
                        let validity = jwk.validity;
                        let mut cache = cache_ref.lock().await;
                        *cache = Some(jwk);
                        println!("Updated JWK keys. Next refresh will be in {:?}", validity);
                        validity
                    }
                    Err(_) => Duration::from_secs(10),
                };
                tokio::time::sleep(duration).await;
            }
        });
    }
}

const X_UID: &str = "X-Uid";
const CLAIMS_KEY: &str = "claims";
const VALID_PUBLIC_KEY: &str = "public";

#[async_trait]
impl Plugin for JwtAuth {
    type Config = JwkConfiguration;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let config = init.config;
        let supergraph_sdl = init.supergraph_sdl.clone();
        let jwk_keys: JsonWebKeys = match fetch_keys(&config).await {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys! Cannot verify user tokens! Shutting down...")
            }
        };
        let mut instance = JwtAuth {
            config,
            jwk_cache: Arc::new(Mutex::new(Some(jwk_keys))),
            public_validator: PublicOperationsValidator::new(supergraph_sdl.to_string()),
        };
        instance.start_key_update();
        Ok(instance)
    }

    fn subgraph_service(&self, _name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        ServiceBuilder::new()
            .map_request(|mut req: subgraph::Request| {
                req.subgraph_request.headers_mut().remove(X_UID);
                if let Ok(Some(claims)) = req.context.get::<_, Claims>(CLAIMS_KEY) {
                    let header_value =
                        HeaderValue::from_str(&claims.sub).expect("id must be ASCII");
                    req.subgraph_request
                        .headers_mut()
                        .insert(X_UID, header_value);
                }
                req
            })
            .service(service)
            .boxed()
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        // Clone/Copy the data we need in our closure.
        let config_ref = Arc::new(self.config.clone());
        let jwk_ref = self.jwk_cache.clone();
        let public_validator = self.public_validator.clone();

        // `ServiceBuilder` provides us with an `checkpoint` method.
        //
        // This method allows us to return ControlFlow::Continue(request) if we want to let the request through,
        // or ControlFlow::Break(response) with a crafted response if we don't want the request to go through.
        ServiceBuilder::new()
            .map_request(move |req: supergraph::Request| {
                // Check if all operations in the request are public
                if let Some(query) = &req.originating_request.body().query {
                    if public_validator.validate(query.to_string()) {
                        println!("validated!");
                        if let Err(e) = req.context.insert(VALID_PUBLIC_KEY, true) {
                            println!(
                                "encountered error inserting VALID_PUBLIC_KEY into context: {:?}",
                                e
                            )
                        }
                    }
                }
                req
            })
            .checkpoint_async(move |req: supergraph::Request| {
                let config_ref = config_ref.clone();
                let jwk_ref = jwk_ref.clone();

                let is_public_request = req
                    .context
                    .get::<_, bool>(VALID_PUBLIC_KEY)
                    .unwrap_or(None)
                    .unwrap_or(false);
                println!("is public req: {:?}", is_public_request);

                async move {
                    let mut failure = None;

                    fn failure_message(
                        context: Context,
                        msg: String,
                        status: StatusCode,
                    ) -> supergraph::Response {
                        supergraph::Response::error_builder()
                            .errors(vec![graphql::Error {
                                message: msg,
                                ..Default::default()
                            }])
                            .status_code(status)
                            .context(context)
                            .build()
                            .expect("response is invalid")
                    }

                    // We are implementing: https://www.rfc-editor.org/rfc/rfc6750
                    // so check for our AUTHORIZATION header.
                    let jwt_value_result =
                        match req.originating_request.headers().get(AUTHORIZATION) {
                            Some(value) => Some(value.to_str()),
                            None =>
                            // If the request is public, allow skipping JWT validation
                            // Otherwise, prepare an HTTP 401 response with a GraphQL error message
                            {
                                if is_public_request {
                                    println!("apparently returning");
                                    return Ok(ControlFlow::Continue(req));
                                }

                                failure = Some(failure_message(
                                    req.context.clone(),
                                    format!("Missing '{}' header", AUTHORIZATION),
                                    StatusCode::UNAUTHORIZED,
                                ));
                                None
                            }
                        };

                    // If we find the header, but can't convert it to a string, let the client know
                    let jwt_value = match jwt_value_result {
                        Some(Ok(value)) => Some(value.trim()),
                        Some(Err(_not_a_string_error)) => {
                            // Prepare an HTTP 400 response with a GraphQL error message
                            failure = Some(failure_message(
                                req.context.clone(),
                                "AUTHORIZATION' header is not convertible to a string".to_string(),
                                StatusCode::BAD_REQUEST,
                            ));
                            None
                        }
                        _ => None,
                    };

                    // We know we have a "space", since we checked above. Split our string
                    // in (at most 2) sections.
                    let jwt_parts = jwt_value.map::<Vec<&str>, _>(|v| v.splitn(2, ' ').collect());
                    // Make sure the format of our message matches our expectations
                    // Technically, the spec is case sensitive, but let's accept
                    // case variations
                    if jwt_value
                        .map(|v| !v.to_uppercase().as_str().starts_with("BEARER "))
                        .unwrap_or(false)
                        || jwt_parts.as_ref().map(|v| v.len() != 2).unwrap_or(false)
                    {
                        // Prepare an HTTP 400 response with a GraphQL error message
                        failure = Some(failure_message(
                            req.context.clone(),
                            format!("'{}' is not correctly formatted", jwt_value.unwrap()),
                            StatusCode::BAD_REQUEST,
                        ));
                    }

                    if let Some(res) = failure {
                        return Ok(ControlFlow::Break(res));
                    }
                    //
                    // Trim off any trailing white space (not valid in BASE64 encoding)
                    let jwt_opt = jwt_parts.map(|v| v[1].trim_end());
                    let jwt = jwt_opt.unwrap();

                    // Validate our token
                    let guard = jwk_ref.lock().await;
                    let keys = match &*guard {
                        Some(jwk) => jwk.keys.clone(),
                        _ => panic!("could not unwrap guard"),
                    };
                    let config = config_ref.clone();
                    let verifier = JwkVerifier::new(
                        JwkConfiguration {
                            jwk_url: config.jwk_url.clone(),
                            audience: config.audience.clone(),
                            issuer: config.issuer.clone(),
                        },
                        keys,
                    );
                    let token_data = match verifier.verify(jwt) {
                        Ok(td) => td,
                        Err(err) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("{jwt} is not authorized: {}", err),
                                StatusCode::UNAUTHORIZED,
                            )));
                        }
                    };

                    match req.context.insert(CLAIMS_KEY, token_data.claims) {
                        Ok(_) => Ok(ControlFlow::Continue(req)),
                        Err(err) => Ok(ControlFlow::Break(failure_message(
                            req.context,
                            format!("couldn't store JWT claims in context: {}", err),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))),
                    }
                }
            })
            .buffered()
            .service(service)
            .boxed()
    }
}

register_plugin!("auth", "jwt", JwtAuth);

#[cfg(test)]
mod tests {
    use apollo_router::plugin::test;
    use apollo_router::plugin::Plugin;
    use apollo_router::services::supergraph;

    use super::*;

    #[tokio::test]
    async fn plugin_registered() {
        let config = serde_json::json!({
            "plugins": {
                "auth.jwt": {
                    "jwk_url": "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
                    "audience": "",
                    "issuer": "",
                }
            }
        });
        apollo_router::TestHarness::builder()
            .configuration_json(config)
            .unwrap()
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn key_is_initialized() {
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let jwt_auth = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes");
        let cache = jwt_auth.jwk_cache.lock().await;
        assert!(cache.is_some(), "cache failed to initialize");
    }

    #[tokio::test]
    async fn key_is_refreshed() {
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let jwt_auth = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes");
        let mut cache = jwt_auth.jwk_cache.lock().await;
        let validity = match &*cache {
            Some(jwk) => jwk.validity,
            None => panic!("could not unwrap mutex"),
        };
        *cache = None;
        drop(cache);

        tokio::time::pause();
        tokio::time::advance(validity).await;
        tokio::time::resume();

        // Give enough time to populate cache
        tokio::time::sleep(Duration::from_secs(1)).await;

        let cache = jwt_auth.jwk_cache.lock().await;
        assert!(cache.is_some());
    }

    #[tokio::test]
    async fn no_authorization_header() {
        let mock_svc = test::MockSupergraphService::new();
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let svc_stack = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes")
            .supergraph_service(mock_svc.boxed());
        let mock_req = supergraph::Request::fake_builder()
            .build()
            .expect("expecting valid request");
        let res = svc_stack.oneshot(mock_req).await.unwrap();
        assert_eq!(res.response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allow_public_request() {
        let mut mock_svc = test::MockSupergraphService::new();
        mock_svc
            .expect_call()
            .once()
            .returning(move |req: supergraph::Request| {
                let id = req.originating_request.headers().get(X_UID);
                assert!(id.is_none());
                supergraph::Response::fake_builder()
                    .status_code(StatusCode::OK)
                    .build()
            });
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let svc_stack = JwtAuth::new(PluginInit::new(
            config,
            Arc::new(
                "
type Query {
    getX(): Int! @public
    getY(): Int! @authenticated
}

type Mutation {
    getZ(): String! @public
}

type Pet @public {
    age: Int!
}"
                .to_string(),
            ),
        ))
        .await
        .expect("initializes")
        .supergraph_service(mock_svc.boxed());
        let mock_req = supergraph::Request::fake_builder()
            .query(
                "
query {
    getX
}

mutation {
    getZ
}
",
            )
            .build()
            .expect("expecting valid request");
        let res = svc_stack.oneshot(mock_req).await.unwrap();
        assert_eq!(res.response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn should_have_bearer() {
        let mock_svc = test::MockSupergraphService::new();
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let svc_stack = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes")
            .supergraph_service(mock_svc.boxed());
        let mock_req = supergraph::Request::fake_builder()
            .header(AUTHORIZATION, "NotBearer boy")
            .build()
            .expect("expecting valid request");
        let res = svc_stack.oneshot(mock_req).await.unwrap();
        assert_eq!(res.response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn should_have_bearer_value() {
        let mock_svc = test::MockSupergraphService::new();
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let svc_stack = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes")
            .supergraph_service(mock_svc.boxed());
        let mock_req = supergraph::Request::fake_builder()
            .header(AUTHORIZATION, "Bearer")
            .build()
            .expect("expecting valid request");
        let res = svc_stack.oneshot(mock_req).await.unwrap();
        assert_eq!(res.response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn should_include_id_in_subgraph_request() {
        let expected_id = "test_id";
        let mut mock_svc = test::MockSubgraphService::new();
        mock_svc
            .expect_call()
            .once()
            .returning(move |req: subgraph::Request| {
                let id = req
                    .subgraph_request
                    .headers()
                    .get(X_UID)
                    .expect("should have UID header");
                assert_eq!(id.to_str().unwrap(), expected_id);
                Ok(subgraph::Response::fake_builder()
                    .status_code(StatusCode::OK)
                    .build())
            });
        let config = JwkConfiguration {
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
        };
        let svc_stack = JwtAuth::new(PluginInit::new(config, Default::default()))
            .await
            .expect("initializes")
            .subgraph_service("test", mock_svc.boxed());
        let mut claims = Claims::default();
        claims.sub = expected_id.to_string();
        let ctx = apollo_router::Context::new();
        ctx.insert(CLAIMS_KEY, claims)
            .expect("should add to context");
        let mock_req = subgraph::Request::fake_builder().context(ctx).build();
        let res = svc_stack.oneshot(mock_req).await.unwrap();
        assert_eq!(res.response.status(), StatusCode::OK);
    }
}
