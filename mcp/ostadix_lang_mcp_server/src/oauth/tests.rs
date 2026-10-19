use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

const PUBLIC: &str = "https://one.example/mcp";
const OTHER: &str = "https://two.example:8443/mcp";
const OWNER: &str = "owner-token-for-test-only-01234567890123456789";
const CALLBACK: &str = "http://127.0.0.1:4567/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG";
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn setup() -> (Directory, OAuth) {
    let dir = Directory(std::env::temp_dir().join(format!("ostadix-oauth-{}", secret().unwrap())));
    let oauth = reopen(&dir);
    (dir, oauth)
}
fn reopen(dir: &Directory) -> OAuth {
    OAuth::open(
        &[PUBLIC.to_owned(), OTHER.to_owned()],
        &dir.0,
        Arc::from(OWNER.as_bytes()),
    )
    .unwrap()
}
async fn call(
    oauth: &OAuth,
    method: Method,
    path: &str,
    content_type: Option<&str>,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "one.example");
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = oauth
        .router()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 1024 * 1024).await.unwrap().to_vec(),
    )
}
async fn form(
    oauth: &OAuth,
    path: &str,
    p: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    call(
        oauth,
        Method::POST,
        path,
        Some("application/x-www-form-urlencoded"),
        serde_urlencoded::to_string(p).unwrap(),
        headers,
    )
    .await
}
async fn register(oauth: &OAuth, method: &str) -> Value {
    let (status, _, bytes) = call(oauth, Method::POST, "/mcp/oauth/register", Some("application/json"),
        json!({"client_name":"Test <client>","redirect_uris":[CALLBACK],"token_endpoint_auth_method":method}).to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}
async fn begin(oauth: &OAuth, client: &str, scope: &str) -> (String, String, String) {
    let challenge = digest(VERIFIER.as_bytes());
    let query = serde_urlencoded::to_string([
        ("client_id", client),
        ("redirect_uri", CALLBACK),
        ("response_type", "code"),
        ("resource", PUBLIC),
        ("scope", scope),
        ("state", "state-from-client"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    let (status, headers, bytes) = call(
        oauth,
        Method::GET,
        &format!("/mcp/oauth/authorize?{query}"),
        None,
        Body::empty(),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "same-origin");
    assert_eq!(headers["content-security-policy"], "default-src 'none'; form-action 'self' http://127.0.0.1:4567; frame-ancestors 'none'; base-uri 'none'");
    let cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let nonce = cookie.split_once('=').unwrap().1.to_owned();
    (cookie, nonce, String::from_utf8(bytes).unwrap())
}
async fn authorize(oauth: &OAuth, client: &str, scope: &str) -> String {
    let (cookie, nonce, html) = begin(oauth, client, scope).await;
    assert!(html.contains("Test &lt;client&gt;"));
    assert!(!html.contains(OWNER));
    let (status, headers, bytes) = form(
        oauth,
        "/mcp/oauth/authorize",
        &[
            ("csrf", &nonce),
            ("owner_token", OWNER),
            ("decision", "allow"),
        ],
        &[("origin", "https://one.example"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let url = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["iss"], "https://one.example/mcp/oauth");
    assert_eq!(query["state"], "state-from-client");
    query["code"].clone()
}
async fn exchange(
    oauth: &OAuth,
    client: &str,
    code: &str,
    verifier: &str,
    redirect: &str,
    resource: &str,
) -> (StatusCode, Value) {
    let (status, _, bytes) = form(
        oauth,
        "/mcp/oauth/token",
        &[
            ("client_id", client),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
            ("resource", resource),
        ],
        &[],
    )
    .await;
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn grant(oauth: &OAuth, client: &str) -> Value {
    let code = authorize(oauth, client, SCOPE).await;
    let (status, token) = exchange(oauth, client, &code, VERIFIER, CALLBACK, PUBLIC).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    token
}
async fn refresh(oauth: &OAuth, client: &str, refresh: &str) -> (StatusCode, Value) {
    let (status, _, bytes) = form(
        oauth,
        "/mcp/oauth/token",
        &[
            ("client_id", client),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("resource", PUBLIC),
        ],
        &[],
    )
    .await;
    (status, serde_json::from_slice(&bytes).unwrap())
}
fn token_headers(token: &str, host: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn discovery_uses_exact_configured_host_and_advertises_pkce() {
    let (_dir, oauth) = setup();
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/mcp/oauth",
    ] {
        let (status, headers, bytes) =
            call(&oauth, Method::GET, path, None, Body::empty(), &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["issuer"], "https://one.example/mcp/oauth");
        assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            value["authorization_response_iss_parameter_supported"],
            true
        );
        assert_eq!(value["client_id_metadata_document_supported"], false);
    }
    let mut headers = token_headers("invalid", "one.example");
    headers.insert(
        "x-forwarded-host",
        HeaderValue::from_static("attacker.example"),
    );
    assert!(oauth
        .challenge(&headers)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("https://one.example/.well-known/"));
    headers.append(header::HOST, HeaderValue::from_static("two.example:8443"));
    assert!(oauth.challenge(&headers).is_none());
    let (status, _, _) = call(
        &oauth,
        Method::GET,
        "/.well-known/oauth-protected-resource/mcp",
        None,
        Body::empty(),
        &[("host", "attacker.example")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn public_urls_and_private_state_are_strict() {
    let (dir, oauth) = setup();
    for url in [
        "http://remote.example/mcp",
        "https://user:pass@host/mcp",
        "https://host/mcp#fragment",
        "https://host/mcp?x=1",
        "https://host/other",
        "file:///mcp",
    ] {
        assert!(OAuth::open(&[url.to_owned()], &dir.0, Arc::from(OWNER.as_bytes())).is_err());
    }
    assert!(OAuth::open(
        &[PUBLIC.to_owned(), PUBLIC.to_owned()],
        &dir.0,
        Arc::from(OWNER.as_bytes())
    )
    .is_err());
    assert!(OAuth::open(
        &[PUBLIC.to_owned()],
        Path::new("relative"),
        Arc::from(OWNER.as_bytes())
    )
    .is_err());
    assert!(
        OAuth::open(&[PUBLIC.to_owned()], &dir.0, Arc::from(OWNER.as_bytes())).is_err(),
        "exclusive state lock"
    );
    drop(oauth);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(OAuth::open(&[PUBLIC.to_owned()], &dir.0, Arc::from(OWNER.as_bytes())).is_err());
    }
}

#[tokio::test]
async fn registration_rejects_open_redirects_but_accepts_exact_loopback_ports() {
    let (_dir, oauth) = setup();
    for uri in [
        "https://user:pass@host/callback",
        "https://host/callback#fragment",
        "http://remote.example/callback",
        "javascript:alert(1)",
        "https://host\\evil/callback",
    ] {
        let (status, _, _) = call(
            &oauth,
            Method::POST,
            "/mcp/oauth/register",
            Some("application/json"),
            json!({"redirect_uris":[uri]}).to_string(),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
    for uri in [
        "https://chat.example/callback",
        "http://localhost:1234/callback",
        "http://127.0.0.1:5678/",
        "http://[::1]:4444/callback",
    ] {
        let (status, _, _) = call(
            &oauth,
            Method::POST,
            "/mcp/oauth/register",
            Some("application/json"),
            json!({"redirect_uris":[uri]}).to_string(),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{uri}");
    }
}

#[tokio::test]
async fn consent_requires_origin_cookie_nonce_owner_and_explicit_decision() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    for origin in [None, Some("null"), Some("https://attacker.example")] {
        let (cookie, nonce, _) = begin(&oauth, id, SCOPE).await;
        let mut headers = vec![("cookie", cookie.as_str())];
        if let Some(origin) = origin {
            headers.push(("origin", origin));
        }
        let (status, _, _) = form(
            &oauth,
            "/mcp/oauth/authorize",
            &[
                ("csrf", &nonce),
                ("owner_token", OWNER),
                ("decision", "allow"),
            ],
            &headers,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (cookie, nonce, _) = begin(&oauth, id, SCOPE).await;
    let (status, _, _) = form(
        &oauth,
        "/mcp/oauth/authorize",
        &[
            ("csrf", &nonce),
            ("owner_token", OWNER),
            ("decision", "allow"),
        ],
        &[("origin", "https://one.example")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = form(
        &oauth,
        "/mcp/oauth/authorize",
        &[
            ("csrf", &nonce),
            ("owner_token", "wrong"),
            ("decision", "allow"),
        ],
        &[("origin", "https://one.example"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = form(
        &oauth,
        "/mcp/oauth/authorize",
        &[
            ("csrf", &nonce),
            ("owner_token", OWNER),
            ("decision", "allow"),
        ],
        &[("origin", "https://one.example"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "consumed CSRF cannot be replayed"
    );
    let (cookie, nonce, _) = begin(&oauth, id, SCOPE).await;
    let (status, headers, _) = form(
        &oauth,
        "/mcp/oauth/authorize",
        &[("csrf", &nonce), ("decision", "deny")],
        &[("origin", "https://one.example"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["referrer-policy"], "no-referrer");
    let url = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let p: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(p["error"], "access_denied");
    assert_eq!(p["iss"], "https://one.example/mcp/oauth");
    assert_eq!(p["state"], "state-from-client");
}

#[tokio::test]
async fn codes_bind_client_resource_redirect_and_pkce_without_consuming_on_mismatch() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let other = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let code = authorize(&oauth, id, SCOPE).await;
    for (client, verifier, redirect, resource) in [
        (
            other["client_id"].as_str().unwrap(),
            VERIFIER,
            CALLBACK,
            PUBLIC,
        ),
        (id, "wrong", CALLBACK, PUBLIC),
        (id, VERIFIER, "http://127.0.0.1:4568/callback", PUBLIC),
        (id, VERIFIER, CALLBACK, OTHER),
    ] {
        let (status, _) = exchange(&oauth, client, &code, verifier, redirect, resource).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, tokens) = exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let headers = token_headers(tokens["access_token"].as_str().unwrap(), "one.example");
    assert!(oauth.authenticate(&headers).is_some());
    assert_eq!(
        exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        oauth.authenticate(&headers).is_none(),
        "code replay revokes the issued family"
    );
}

#[tokio::test]
async fn refresh_rotates_preserves_identity_and_replay_revokes_all_descendants() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let first = grant(&oauth, id).await;
    let first_headers = token_headers(first["access_token"].as_str().unwrap(), "one.example");
    let identity = oauth.authenticate(&first_headers).unwrap();
    let (status, second) = refresh(&oauth, id, first["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_ne!(first["refresh_token"], second["refresh_token"]);
    let second_headers = token_headers(second["access_token"].as_str().unwrap(), "one.example");
    assert_eq!(oauth.authenticate(&second_headers), Some(identity));
    assert!(oauth
        .authenticate(&token_headers(
            second["access_token"].as_str().unwrap(),
            "two.example:8443"
        ))
        .is_none());
    assert_eq!(
        refresh(&oauth, id, first["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(oauth.authenticate(&first_headers).is_none());
    assert!(oauth.authenticate(&second_headers).is_none());
    assert_eq!(
        refresh(&oauth, id, second["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn expired_codes_and_tokens_are_rejected() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let code = authorize(&oauth, id, SCOPE).await;
    oauth
        .transact(|disk| {
            disk.codes
                .get_mut(&digest(code.as_bytes()))
                .unwrap()
                .expires = now() - 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let token = grant(&oauth, id).await;
    let access = token["access_token"].as_str().unwrap();
    oauth
        .transact(|disk| {
            disk.access
                .get_mut(&digest(access.as_bytes()))
                .unwrap()
                .expires = now() - 1;
            Ok(())
        })
        .unwrap();
    assert!(oauth
        .authenticate(&token_headers(access, "one.example"))
        .is_none());
    let refresh_token = token["refresh_token"].as_str().unwrap();
    oauth
        .transact(|disk| {
            disk.refresh
                .get_mut(&digest(refresh_token.as_bytes()))
                .unwrap()
                .expires = now() - 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        refresh(&oauth, id, refresh_token).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn durable_state_survives_restart_without_persisting_plaintext_secrets() {
    let (dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let token = grant(&oauth, id).await;
    let access = token["access_token"].as_str().unwrap();
    let refresh_token = token["refresh_token"].as_str().unwrap();
    let identity = oauth
        .authenticate(&token_headers(access, "one.example"))
        .unwrap();
    let saved = std::fs::read_to_string(dir.0.join("state.json")).unwrap();
    for secret in [OWNER, access, refresh_token] {
        assert!(!saved.contains(secret));
    }
    drop(oauth);
    let oauth = reopen(&dir);
    assert_eq!(
        oauth.authenticate(&token_headers(access, "one.example")),
        Some(identity)
    );
    assert_eq!(refresh(&oauth, id, refresh_token).await.0, StatusCode::OK);
}

#[tokio::test]
async fn revocation_is_client_bound_and_durable() {
    let (dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let other = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let token = grant(&oauth, id).await;
    let access = token["access_token"].as_str().unwrap();
    for other_id in [other["client_id"].as_str().unwrap(), id] {
        let (status, _, _) = form(
            &oauth,
            "/mcp/oauth/revoke",
            &[("client_id", other_id), ("token", access)],
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            oauth
                .authenticate(&token_headers(access, "one.example"))
                .is_some(),
            other_id != id
        );
    }
    drop(oauth);
    let oauth = reopen(&dir);
    assert!(oauth
        .authenticate(&token_headers(access, "one.example"))
        .is_none());
}

#[tokio::test]
async fn persistence_failure_disables_all_oauth_authentication() {
    let (dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let token = grant(&oauth, id).await;
    let access = token["access_token"].as_str().unwrap();
    assert!(oauth
        .authenticate(&token_headers(access, "one.example"))
        .is_some());
    std::fs::remove_file(dir.0.join("state.json")).unwrap();
    std::fs::create_dir(dir.0.join("state.json")).unwrap();
    let (status, _, _) = form(
        &oauth,
        "/mcp/oauth/revoke",
        &[("client_id", id), ("token", access)],
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(oauth
        .authenticate(&token_headers(access, "one.example"))
        .is_none());
    assert_eq!(
        refresh(&oauth, id, token["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn confidential_clients_require_registered_auth_method() {
    use base64::engine::general_purpose::STANDARD;
    let (_dir, oauth) = setup();
    for method in ["client_secret_post", "client_secret_basic"] {
        let client = register(&oauth, method).await;
        let id = client["client_id"].as_str().unwrap();
        let code = authorize(&oauth, id, SCOPE).await;
        assert_eq!(
            exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let secret = client["client_secret"].as_str().unwrap();
        let mut values = vec![
            ("client_id", id),
            ("grant_type", "authorization_code"),
            ("resource", PUBLIC),
            ("code", code.as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
        ];
        let basic = format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")));
        let mut headers = Vec::new();
        if method == "client_secret_post" {
            values.push(("client_secret", secret));
        } else {
            headers.push(("authorization", basic.as_str()));
        }
        let (status, _, bytes) = form(&oauth, "/mcp/oauth/token", &values, &headers).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[tokio::test]
async fn offline_access_scope_is_preserved_and_unknown_scopes_rejected() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let code = authorize(&oauth, id, "offline_access ostadix:execute").await;
    let (status, token) = exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(token["scope"], "ostadix:execute offline_access");
    assert!(oauth
        .authenticate(&token_headers(
            token["access_token"].as_str().unwrap(),
            "one.example"
        ))
        .is_some());
    assert!(normalize_scope("ostadix:execute admin").is_none());
    assert!(normalize_scope("offline_access").is_none());
    assert!(normalize_scope("ostadix:execute ostadix:execute").is_none());
}

#[tokio::test]
async fn endpoints_bound_bodies_duplicates_and_registration_rate() {
    let (_dir, oauth) = setup();
    let (status, _, _) = call(
        &oauth,
        Method::POST,
        "/mcp/oauth/register",
        Some("application/json"),
        "x".repeat(MAX_BODY + 1),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = form(
        &oauth,
        "/mcp/oauth/token",
        &[
            ("client_id", "one"),
            ("client_id", "two"),
            ("resource", PUBLIC),
        ],
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resource = oauth.0.resources["one.example"].clone();
    for _ in 0..60 {
        oauth.rate(&resource, "register", 60);
    }
    let (status, _, _) = call(
        &oauth,
        Method::POST,
        "/mcp/oauth/register",
        Some("application/json"),
        json!({"redirect_uris":[CALLBACK]}).to_string(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, headers, _) = call(
        &oauth,
        Method::OPTIONS,
        "/mcp/oauth/token",
        None,
        Body::empty(),
        &[("origin", "https://client.example")],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
}

#[test]
fn native_redirect_matching_allows_only_loopback_port_changes() {
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        assert!(redirect_matches(
            &format!("http://{host}/callback?x=1"),
            &format!("http://{host}:49152/callback?x=1")
        ));
    }
    for other in [
        "http://localhost:49152/callback",
        "http://127.0.0.2:49152/callback",
        "https://127.0.0.1:49152/callback",
        "http://127.0.0.1:49152/other",
        "http://127.0.0.1:49152/callback?x=1",
    ] {
        assert!(
            !redirect_matches("http://127.0.0.1/callback", other),
            "{other}"
        );
    }
    assert!(!redirect_matches(
        "https://client.example/callback",
        "https://client.example:8443/callback"
    ));
}

#[tokio::test]
async fn stalled_oauth_body_has_bounded_deadline() {
    let (_dir, oauth) = setup();
    let stream = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
    let started = std::time::Instant::now();
    let (status, _, _) = call(
        &oauth,
        Method::POST,
        "/mcp/oauth/register",
        Some("application/json"),
        Body::from_stream(stream),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
}

#[tokio::test]
async fn refresh_normalizes_scope_order_without_expanding_permissions() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let code = authorize(&oauth, id, "ostadix:execute offline_access").await;
    let (_, token) = exchange(&oauth, id, &code, VERIFIER, CALLBACK, PUBLIC).await;
    let (status, _, bytes) = form(
        &oauth,
        "/mcp/oauth/token",
        &[
            ("client_id", id),
            ("grant_type", "refresh_token"),
            ("resource", PUBLIC),
            ("refresh_token", token["refresh_token"].as_str().unwrap()),
            ("scope", "offline_access ostadix:execute"),
        ],
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let token = grant(&oauth, id).await;
    let (status, _, bytes) = form(
        &oauth,
        "/mcp/oauth/token",
        &[
            ("client_id", id),
            ("grant_type", "refresh_token"),
            ("resource", PUBLIC),
            ("refresh_token", token["refresh_token"].as_str().unwrap()),
            ("scope", "ostadix:execute offline_access"),
        ],
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        refresh(&oauth, id, token["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn queued_readers_and_writers_observe_persistence_failure_latch() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let token = grant(&oauth, client["client_id"].as_str().unwrap()).await;
    let headers = token_headers(token["access_token"].as_str().unwrap(), "one.example");
    let guard = oauth.0.runtime.lock().unwrap();
    let queued = oauth.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        sender.send(()).unwrap();
        queued.authenticate(&headers)
    });
    receiver.recv().unwrap();
    let queued = oauth.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        sender.send(()).unwrap();
        queued.transact(|_| Ok(()))
    });
    receiver.recv().unwrap();
    // Give both workers a chance to block on the held state lock; correctness
    // does not depend on scheduling because the latch is checked on both sides.
    std::thread::sleep(std::time::Duration::from_millis(20));
    oauth.0.failed.store(true, Ordering::Release);
    drop(guard);
    assert!(reader.join().unwrap().is_none());
    assert!(writer.join().unwrap().is_err());
}

#[tokio::test]
async fn authorization_errors_redirect_only_after_client_and_callback_validation() {
    let (_dir, oauth) = setup();
    let client = register(&oauth, "none").await;
    let id = client["client_id"].as_str().unwrap();
    let challenge = digest(VERIFIER.as_bytes());
    let base = BTreeMap::from([
        ("client_id", id),
        ("redirect_uri", CALLBACK),
        ("response_type", "code"),
        ("resource", PUBLIC),
        ("scope", SCOPE),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", "preserve-state"),
    ]);
    for (key, value, expected) in [
        ("scope", "admin", "invalid_scope"),
        ("response_type", "token", "unsupported_response_type"),
        ("code_challenge_method", "plain", "invalid_request"),
        ("code_challenge", "bad", "invalid_request"),
        ("resource", OTHER, "invalid_target"),
    ] {
        let mut p = base.clone();
        p.insert(key, value);
        let query = serde_urlencoded::to_string(p).unwrap();
        let (status, headers, _) = call(
            &oauth,
            Method::GET,
            &format!("/mcp/oauth/authorize?{query}"),
            None,
            Body::empty(),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{key}");
        let url = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
        let p: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(p["error"], expected);
        assert_eq!(p["state"], "preserve-state");
        assert_eq!(p["iss"], "https://one.example/mcp/oauth");
    }
    for (key, value) in [
        ("client_id", "unknown"),
        ("redirect_uri", "https://attacker.example/callback"),
        ("redirect_uri", "http://127.0.0.1:4567/other"),
    ] {
        let mut p = base.clone();
        p.insert(key, value);
        p.insert("scope", "admin");
        let query = serde_urlencoded::to_string(p).unwrap();
        let (status, headers, _) = call(
            &oauth,
            Method::GET,
            &format!("/mcp/oauth/authorize?{query}"),
            None,
            Body::empty(),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!headers.contains_key(header::LOCATION));
    }
}
