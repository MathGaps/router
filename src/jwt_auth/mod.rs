use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::{subgraph, supergraph};
use apollo_router::{graphql, register_plugin, Context};
use async_trait::async_trait;
use cookie::time::Duration as CookieDuration;
use cookie::Cookie;
use http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use http::{HeaderValue, StatusCode};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tower::{BoxError, ServiceBuilder, ServiceExt};

use self::fetch_keys::{fetch_keys, JsonWebKeys};
use self::verifier::{Claims, JwkVerifier};

mod fetch_keys;
mod get_max_age;
mod verifier;

#[derive(Debug, Default, Deserialize, JsonSchema, Clone)]
pub(crate) struct JwkConfiguration {
    pub(crate) host: String,
    pub(crate) oso_cloud_token: String,

    pub(crate) jwk_url: String,
    pub(crate) audience: String,
    pub(crate) issuer: String,
}

#[derive(Clone, Default)]
struct JwtAuth {
    config: JwkConfiguration,
    jwk_cache: Arc<Mutex<Option<JsonWebKeys>>>,
    impersonation_cache: ImpersonationCache,
}

#[derive(Clone, Default, Eq, Hash, PartialEq)]
struct Impersonation {
    impersonator: String,
    student: String,
}

#[derive(Clone)]
struct ImpersonationCache(moka::sync::Cache<Impersonation, bool>);

impl Default for ImpersonationCache {
    fn default() -> Self {
        Self(moka::sync::Cache::new(1000))
    }
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

const X_UID_HEADER: &str = "X-Uid";
const X_IMPERSONATING_UID_HEADER: &str = "X-Impersonating-Uid";
const SESSION_REFRESH_COOKIE: &str = "router_session_refresh";
const OSO_CLOUD_API: &str = "https://cloud.osohq.com/api/";
const JWT_KEY: &str = "jwt";
const CLAIMS_KEY: &str = "claims";
const IMPERSONATING_UID_KEY: &str = "impersonating_uid";

#[async_trait]
impl Plugin for JwtAuth {
    type Config = JwkConfiguration;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let config = init.config;
        let jwk_keys: JsonWebKeys = match fetch_keys(&config).await {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys! Cannot verify user tokens! Shutting down...")
            }
        };
        let mut instance = JwtAuth {
            config,
            jwk_cache: Arc::new(Mutex::new(Some(jwk_keys))),
            impersonation_cache: Default::default(),
        };
        instance.start_key_update();
        Ok(instance)
    }

    fn subgraph_service(&self, _name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        ServiceBuilder::new()
            .map_request(|mut req: subgraph::Request| {
                let headers = req.subgraph_request.headers_mut();
                headers.remove(X_UID_HEADER);
                headers.remove(X_IMPERSONATING_UID_HEADER);

                if let Ok(Some(claims)) = req.context.get::<_, Claims>(CLAIMS_KEY) {
                    let header_value =
                        HeaderValue::from_str(&claims.sub).expect("id must be ASCII");
                    headers.insert(X_UID_HEADER, header_value);
                }
                if let Ok(Some(impersonating)) = req.context.get::<_, String>(IMPERSONATING_UID_KEY)
                {
                    let header_value = HeaderValue::from_str(&impersonating)
                        .expect("impersonating id must be ASCII");
                    headers.insert(X_IMPERSONATING_UID_HEADER, header_value);
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
        let host = config_ref.host.clone();
        let impersonation_cache = self.impersonation_cache.clone();

        // `ServiceBuilder` provides us with an `checkpoint` method.
        //
        // This method allows us to return ControlFlow::Continue(request) if we want to let the request through,
        // or ControlFlow::Break(response) with a crafted response if we don't want the request to go through.
        ServiceBuilder::new()
            .checkpoint_async(move |req: supergraph::Request| {
                let config_ref = config_ref.clone();
                let jwk_ref = jwk_ref.clone();
                let impersonation_cache = impersonation_cache.0.clone();

                async move {
                    let mut failure = None;

                    fn failure_message(
                        context: Context,
                        msg: String,
                        status: StatusCode,
                    ) -> supergraph::Response {
                        supergraph::Response::error_builder()
                            .error(graphql::Error::builder().message(msg).build())
                            .status_code(status)
                            .context(context)
                            .build()
                            .expect("response is invalid")
                    }

                    // We are implementing: https://www.rfc-editor.org/rfc/rfc6750
                    // so check for our AUTHORIZATION header.
                    let jwt_value_result = match req.supergraph_request.headers().get(AUTHORIZATION)
                    {
                        Some(value) => Some(value.to_str()),
                        None => return Ok(ControlFlow::Continue(req)),
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
                    if let Err(e) = req.context.insert(JWT_KEY, jwt.to_string()) {
                        println!("error inserting JWT_KEY into context: {}", e);
                    }

                    // Validate our token
                    let guard = jwk_ref.lock().await;
                    let keys = match &*guard {
                        Some(jwk) => jwk.keys.clone(),
                        _ => panic!("could not unwrap guard"),
                    };
                    let config = config_ref.clone();
                    let verifier = JwkVerifier::new(
                        JwkConfiguration {
                            host: config.host.clone(),
                            jwk_url: config.jwk_url.clone(),
                            audience: config.audience.clone(),
                            issuer: config.issuer.clone(),
                            oso_cloud_token: config.oso_cloud_token.clone(),
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
                    let authorized_uid = token_data.claims.sub.clone();

                    match req.context.insert(CLAIMS_KEY, token_data.claims) {
                        Ok(_) => {}
                        Err(err) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("couldn't store JWT claims in context: {}", err),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                    };

                    // Verify authorized user can impersonate
                    let impersonating_uid = match req
                        .supergraph_request
                        .headers()
                        .get(X_IMPERSONATING_UID_HEADER)
                        .map(|h| h.to_str())
                    {
                        Some(Ok(impersonating)) => impersonating.to_owned(),
                        Some(Err(err)) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!(
                                    "error converting impersonating uid header to string: {}",
                                    err
                                ),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                        None => return Ok(ControlFlow::Continue(req)),
                    };
                    if impersonating_uid == authorized_uid {
                        return Ok(ControlFlow::Continue(req));
                    }
                    match req
                        .context
                        .insert(IMPERSONATING_UID_KEY, impersonating_uid.clone())
                    {
                        Ok(_) => {}
                        Err(err) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("couldn't store impersonating uid in context: {}", err),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                    };

                    // Check if authorization request has been cached
                    let cache = impersonation_cache.clone();
                    match cache.get(&Impersonation {
                        impersonator: authorized_uid.clone(),
                        student: impersonating_uid.clone(),
                    }) {
                        Some(true) => return Ok(ControlFlow::Continue(req)),
                        Some(false) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!(
                                    "user {} is not authorized to impersonate user {}",
                                    authorized_uid, impersonating_uid
                                ),
                                StatusCode::UNAUTHORIZED,
                            )))
                        }
                        None => {}
                    }

                    let oso_cloud_token = config.oso_cloud_token.clone();
                    let body = json!({
                        "fact": {
                            "predicate": "can_impersonate",
                            "args": [
                                {
                                    "type": "User",
                                    "id": authorized_uid,
                                },
                                {
                                    "type": "User",
                                    "id": impersonating_uid,
                                },
                            ]
                        }
                    });
                    let res = match reqwest::Client::new()
                        .post(format!("{}/query", OSO_CLOUD_API))
                        .json(&body)
                        .bearer_auth(oso_cloud_token)
                        .send()
                        .await
                    {
                        Ok(res) => res,
                        Err(err) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("query request to oso-cloud failed: {}", err),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                    };
                    let payload = match res.json::<serde_json::Value>().await {
                        Ok(payload) => payload,
                        Err(err) => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("could not deserialize oso-cloud response: {}", err),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                    };
                    match payload.get("results") {
                        Some(serde_json::Value::Array(results)) => {
                            if results.is_empty() {
                                Ok(ControlFlow::Break(failure_message(
                                    req.context,
                                    format!(
                                        "user {} is not authorized to impersonate user {}",
                                        authorized_uid, impersonating_uid
                                    ),
                                    StatusCode::UNAUTHORIZED,
                                )))
                            } else {
                                Ok(ControlFlow::Continue(req))
                            }
                        }
                        _ => {
                            return Ok(ControlFlow::Break(failure_message(
                                req.context,
                                format!("could not extract results from payload: {}", payload),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )))
                        }
                    }
                }
            })
            .map_request(move |mut req: supergraph::Request| {
                // Refresh the session cookie if required
                let raw_cookies = match req
                    .supergraph_request
                    .headers()
                    .get(COOKIE)
                    .map(|cookie_header| cookie_header.to_str())
                {
                    Some(Ok(cookies)) => cookies,
                    _ => return req,
                };

                match raw_cookies.split("; ").find(|&c| match c.split_once('=') {
                    Some((k, _)) => k == SESSION_REFRESH_COOKIE,
                    _ => false,
                }) {
                    Some(_) => req,
                    _ => {
                        let jwt = match req.context.get::<_, String>(JWT_KEY) {
                            Ok(Some(jwt)) => jwt,
                            _ => return req,
                        };
                        let thread_host = host.clone();
                        tokio::spawn(async move {
                            let client = reqwest::Client::new();
                            if let Ok(req) = client
                                .post(format!("{}/accounts/login", thread_host))
                                .bearer_auth(jwt)
                                .build()
                            {
                                if let Err(e) = client.execute(req).await {
                                    println!(
                                        "error while executing request at accounts/login: {}",
                                        e
                                    )
                                }
                            }
                        });
                        let refresh_cookie = Cookie::build(SESSION_REFRESH_COOKIE, "1")
                            .domain(host.clone())
                            .secure(true)
                            .http_only(true)
                            .same_site(cookie::SameSite::Strict)
                            .max_age(CookieDuration::minutes(15))
                            .finish();
                        let header_value = match HeaderValue::from_str(&refresh_cookie.to_string())
                        {
                            Ok(hv) => hv,
                            _ => return req,
                        };
                        req.supergraph_request
                            .headers_mut()
                            .insert(SET_COOKIE, header_value);
                        req
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
                    "host": "tuterodev.com.au",
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
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
    async fn session_refresh_cookie_created() {
        //     let mut mock_svc = test::MockSupergraphService::new();
        //     mock_svc
        //         .expect_call()
        //         .once()
        //         .returning(move |req: supergraph::Request| {
        //             let src = req
        //                 .supergraph_request
        //                 .headers()
        //                 .get(SESSION_REFRESH_COOKIE)
        //                 .expect("should have session refresh header");
        //             assert_eq!(src.to_str().unwrap(), "1");
        //             supergraph::Response::fake_builder()
        //                 .status_code(StatusCode::OK)
        //                 .build()
        //         });
        //     let config = JwkConfiguration {
        //         host: "tuterodev.com".to_string(),
        //         jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
        //         audience: "".to_string(),
        //         issuer: "".to_string(),
        //     };
        //     let svc_stack = JwtAuth::new(PluginInit::new(config, Default::default()))
        //         .await
        //         .expect("initializes")
        //         .supergraph_service(mock_svc.boxed());
        //     let mock_req = supergraph::Request::fake_builder()
        //         .header(AUTHORIZATION, "Bearer yrdya")
        //         .build()
        //         .expect("expecting valid request");
        //     let res = svc_stack.oneshot(mock_req).await.unwrap();
        //     assert_eq!(res.response.status(), StatusCode::OK);
        todo!("Issue a token so that this test can be finished");
    }

    #[tokio::test]
    async fn no_authorization_header() {
        let mock_svc = test::MockSupergraphService::new();
        let config = JwkConfiguration {
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
                let id = req.supergraph_request.headers().get(X_UID_HEADER);
                assert!(id.is_none());
                supergraph::Response::fake_builder()
                    .status_code(StatusCode::OK)
                    .build()
            });
        let config = JwkConfiguration {
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
                    .get(X_UID_HEADER)
                    .expect("should have UID header");
                assert_eq!(id.to_str().unwrap(), expected_id);
                Ok(subgraph::Response::fake_builder()
                    .status_code(StatusCode::OK)
                    .build())
            });
        let config = JwkConfiguration {
            host: "tuterodev.com".to_string(),
            jwk_url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "".to_string(),
            issuer: "".to_string(),
            oso_cloud_token: "".to_string(),
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
