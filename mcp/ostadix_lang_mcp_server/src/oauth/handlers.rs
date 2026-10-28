//! Discovery, bounded client registration, and owner consent.
mod exchange;
use super::*;
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use model::{Client, Code};
use serde::Deserialize;
use serde_json::{json, Value};

type Params = BTreeMap<String, String>;
#[derive(Clone, Copy)]
struct Fault(StatusCode, &'static str, &'static str);
impl Fault {
    fn invalid(description: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request", description)
    }
    fn grant() -> Self {
        Self(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "The grant is invalid, expired, or already used",
        )
    }
    fn client() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
        )
    }
    fn internal() -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "OAuth state is unavailable; try again later",
        )
    }
    fn response(self) -> Response {
        let mut response = (
            self.0,
            Json(json!({"error":self.1,"error_description":self.2})),
        )
            .into_response();
        if self.0 == StatusCode::UNAUTHORIZED && self.1 == "invalid_client" {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"ostadix-oauth\""),
            );
        }
        finish(response, true)
    }
}
fn finish(mut response: Response, cors: bool) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if cors {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    response
}
fn resource(oauth: &OAuth, headers: &HeaderMap) -> Result<Resource, Fault> {
    oauth
        .resource(headers)
        .cloned()
        .ok_or(Fault::invalid("Unrecognized or duplicate Host"))
}
fn limited(
    oauth: &OAuth,
    resource: &Resource,
    operation: &'static str,
    limit: u32,
) -> Result<(), Fault> {
    if oauth.0.failed.load(Ordering::Acquire) {
        return Err(Fault::internal());
    }
    if oauth.rate(resource, operation, limit) {
        Ok(())
    } else {
        Err(Fault(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "OAuth request limit reached; try again later",
        ))
    }
}
fn params(raw: &[u8]) -> Result<Params, Fault> {
    if raw.len() > MAX_BODY {
        return Err(Fault::invalid("Request exceeds OAuth size limit"));
    }
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_bytes(raw).map_err(|_| Fault::invalid("Invalid form encoding"))?;
    let mut output = Params::new();
    for (name, value) in pairs {
        if output.insert(name, value).is_some() {
            return Err(Fault::invalid("Duplicate OAuth parameter"));
        }
    }
    Ok(output)
}
fn required<'a>(params: &'a Params, key: &str) -> Result<&'a str, Fault> {
    params
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(Fault::invalid("Missing required OAuth parameter"))
}
async fn body(request: Request, kind: &'static str) -> Result<(HeaderMap, Vec<u8>), Fault> {
    if one_header(request.headers(), header::CONTENT_TYPE.as_str())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        != Some(kind)
    {
        return Err(Fault(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "Unsupported Content-Type",
        ));
    }
    let (parts, body) = request.into_parts();
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(10), to_bytes(body, MAX_BODY))
        .await
        .map_err(|_| {
            Fault(
                StatusCode::REQUEST_TIMEOUT,
                "invalid_request",
                "OAuth request body timed out",
            )
        })?
        .map_err(|_| Fault::invalid("Request exceeds OAuth size limit"))?;
    Ok((parts.headers, bytes.to_vec()))
}
pub(super) async fn preflight(State(oauth): State<OAuth>, request: Request) -> Response {
    if let Err(error) = resource(&oauth, request.headers()) {
        return error.response();
    }
    let mut response = finish(StatusCode::NO_CONTENT.into_response(), true);
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    response
}
pub(super) async fn resource_metadata(State(oauth): State<OAuth>, headers: HeaderMap) -> Response {
    match resource(&oauth, &headers) {
        Ok(r) => finish(
            Json(json!({"resource":r.resource,"resource_name":"OSTADIX",
            "authorization_servers":[r.issuer],"scopes_supported":[SCOPE,"offline_access"],
            "bearer_methods_supported":["header"]}))
            .into_response(),
            true,
        ),
        Err(error) => error.response(),
    }
}
pub(super) async fn server_metadata(State(oauth): State<OAuth>, headers: HeaderMap) -> Response {
    match resource(&oauth, &headers) {
        Ok(r) => finish(Json(json!({"issuer":r.issuer,
            "authorization_endpoint":format!("{}/authorize",r.issuer),
            "token_endpoint":format!("{}/token",r.issuer),
            "registration_endpoint":format!("{}/register",r.issuer),
            "revocation_endpoint":format!("{}/revoke",r.issuer),
            "response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],
            "code_challenge_methods_supported":["S256"],"scopes_supported":[SCOPE,"offline_access"],
            "token_endpoint_auth_methods_supported":["none","client_secret_post","client_secret_basic"],
            "revocation_endpoint_auth_methods_supported":["none","client_secret_post","client_secret_basic"],
            "authorization_response_iss_parameter_supported":true,
            "client_id_metadata_document_supported":false})).into_response(), true),
        Err(error) => error.response(),
    }
}

#[derive(Deserialize)]
struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    scope: Option<String>,
}
pub(super) async fn register(State(oauth): State<OAuth>, request: Request) -> Response {
    let result = async {
        let r = resource(&oauth, request.headers())?;
        limited(&oauth, &r, "register", 60)?;
        let (_, bytes) = body(request, "application/json").await?;
        let registration: Registration = serde_json::from_slice(&bytes).map_err(|_| Fault::invalid("Invalid registration JSON"))?;
        let name = registration.client_name.unwrap_or_else(|| "MCP client".to_owned());
        if name.len() > 128 || name.chars().any(char::is_control) || registration.redirect_uris.is_empty()
            || registration.redirect_uris.len() > 16 { return Err(Fault::invalid("Invalid client name or redirect list")); }
        for redirect in &registration.redirect_uris {
            safe_url(redirect).map_err(|_| Fault(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "Redirects must be HTTPS or HTTP loopback, without credentials or fragment"))?;
        }
        let method = registration.token_endpoint_auth_method.unwrap_or_else(|| "none".to_owned());
        if !matches!(method.as_str(), "none" | "client_secret_post" | "client_secret_basic")
            || registration.grant_types.as_ref().is_some_and(|values| values.is_empty() || values.iter().any(|v| v != "authorization_code" && v != "refresh_token"))
            || registration.response_types.as_ref().is_some_and(|values| values.as_slice() != ["code"])
            || registration.scope.as_deref().is_some_and(|scope| normalize_scope(scope).is_none()) {
            return Err(Fault(StatusCode::BAD_REQUEST, "invalid_client_metadata", "Unsupported client authorization metadata"));
        }
        let id = secret().map_err(|_| Fault::internal())?;
        let client_secret = if method == "none" { None } else { Some(secret().map_err(|_| Fault::internal())?) };
        let created = now();
        let client = Client { name: name.clone(), redirects: registration.redirect_uris.clone(),
            auth_method: method.clone(), secret_hash: client_secret.as_ref().map(|v| digest(v.as_bytes())),
            resource: r.resource, created, used: false };
        oauth.transact(|disk| {
            if disk.clients.len() >= MAX_CLIENTS { bail!("client capacity exceeded"); }
            disk.clients.insert(id.clone(), client);
            Ok(())
        }).map_err(|_| Fault::internal())?;
        let mut response = json!({"client_id":id,"client_id_issued_at":created,"client_name":name,
            "redirect_uris":registration.redirect_uris,"token_endpoint_auth_method":method,
            "grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":SCOPE});
        if let Some(secret) = client_secret {
            response["client_secret"] = Value::String(secret);
            response["client_secret_expires_at"] = json!(0);
        }
        Ok(finish((StatusCode::CREATED, Json(response)).into_response(), true))
    }.await;
    result.unwrap_or_else(Fault::response)
}

fn authorization_client(oauth: &OAuth, r: &Resource, p: &Params) -> Result<Client, Fault> {
    let client_id = required(p, "client_id")?;
    let redirect = required(p, "redirect_uri")?;
    let runtime = oauth.0.runtime.lock().map_err(|_| Fault::internal())?;
    let client = runtime.disk.clients.get(client_id).ok_or(Fault::invalid(
        "Unknown client; register this application first",
    ))?;
    if client.resource != r.resource
        || !client
            .redirects
            .iter()
            .any(|registered| redirect_matches(registered, redirect))
    {
        return Err(Fault::invalid(
            "Redirect URI does not exactly match this registered client",
        ));
    }
    if p.get("state").is_some_and(|v| v.len() > 1024) {
        return Err(Fault::invalid("State exceeds length limit"));
    }
    Ok(client.clone())
}
fn validate_authorization(
    r: &Resource,
    p: &Params,
    client: Client,
) -> Result<(Pending, String), Fault> {
    let client_id = required(p, "client_id")?;
    let redirect = required(p, "redirect_uri")?;
    if required(p, "response_type")? != "code" {
        return Err(Fault(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only response_type=code is supported",
        ));
    }
    if required(p, "resource")? != r.resource {
        return Err(Fault(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Resource must exactly match this MCP URL",
        ));
    }
    let challenge = required(p, "code_challenge")?;
    if required(p, "code_challenge_method")? != "S256"
        || challenge.len() != 43
        || URL_SAFE_NO_PAD
            .decode(challenge)
            .map_or(true, |v| v.len() != 32)
    {
        return Err(Fault::invalid(
            "Authorization requires a valid S256 PKCE challenge",
        ));
    }
    let scope = p.get("scope").map_or(SCOPE, String::as_str);
    let scope = normalize_scope(scope).ok_or(Fault(
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "Scope must include ostadix:execute; offline_access is optional",
    ))?;
    if p.get("state").is_some_and(|v| v.len() > 1024) {
        return Err(Fault::invalid("State exceeds length limit"));
    }
    Ok((
        Pending {
            client: client_id.to_owned(),
            redirect: redirect.to_owned(),
            resource: r.resource.clone(),
            scope: scope.to_owned(),
            challenge: challenge.to_owned(),
            state: p.get("state").cloned(),
            expires: now() + CODE_TTL,
        },
        client.name.clone(),
    ))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn cookie_name(r: &Resource) -> &'static str {
    if r.secure {
        "__Secure-ostadix_oauth"
    } else {
        "ostadix_oauth"
    }
}
fn html(body: String, callback: &str) -> Result<Response, Fault> {
    let mut response = finish(Html(body).into_response(), false);
    // no-referrer makes browsers send Origin:null on navigation POSTs. Keep
    // this same-origin form verifiable without leaking a Referer to callbacks.
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("same-origin"));
    // Chromium applies form-action to the authorization POST's redirect too.
    // Allow only the validated callback's origin in addition to our own POST.
    let callback_origin = safe_url(callback)
        .map_err(|_| Fault::internal())?
        .origin()
        .ascii_serialization();
    let policy = format!("default-src 'none'; form-action 'self' {callback_origin}; frame-ancestors 'none'; base-uri 'none'");
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_str(&policy).map_err(|_| Fault::internal())?,
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    Ok(response)
}

pub(super) async fn authorize_get(State(oauth): State<OAuth>, request: Request) -> Response {
    let result = (|| {
        let r = resource(&oauth, request.headers())?;
        limited(&oauth, &r, "authorize", 300)?;
        let p = params(request.uri().query().unwrap_or("").as_bytes())?;
        // Only a validated client/callback pair may receive OAuth redirects.
        let client = authorization_client(&oauth, &r, &p)?;
        let (pending, client_name) = match validate_authorization(&r, &p, client) {
            Ok(value) => value,
            Err(error) => {
                return redirect_uri(
                    required(&p, "redirect_uri")?,
                    p.get("state").map(String::as_str),
                    &r,
                    "error",
                    error.1,
                )
            }
        };
        let nonce = secret().map_err(|_| Fault::internal())?;
        let page = format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connect to OSTADIX</title><body><main><h1>Connect to OSTADIX</h1><p>Application: <strong>{}</strong> (name supplied by the application)</p><p>Client ID: <code>{}</code></p><p>Callback: <code>{}</code></p><p>Server: <code>{}</code></p><p>Allowing this connection grants access to all OSTADIX tools on this host, including program execution, files, and native commands. Approve only an application you trust.</p><form method=\"post\" action=\"/mcp/oauth/authorize\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><p><label>Server owner token <input type=\"password\" name=\"owner_token\" autocomplete=\"off\" maxlength=\"4096\"></label></p><button type=\"submit\" name=\"decision\" value=\"allow\">Allow connection</button> <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></main></body></html>",
            escape(&client_name), escape(&pending.client), escape(&pending.redirect), escape(&r.resource), nonce);
        let mut response = html(page, &pending.redirect)?;
        oauth
            .put_pending(&nonce, pending)
            .map_err(|_| Fault::internal())?;
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
            "{}={nonce}; Path=/mcp/oauth/authorize; HttpOnly; SameSite=Lax; Max-Age={CODE_TTL}{}",
            cookie_name(&r), if r.secure { "; Secure" } else { "" }))
            .map_err(|_| Fault::internal())?,
        );
        Ok(response)
    })();
    result.unwrap_or_else(Fault::response)
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut value = None;
    for header in headers.get_all(header::COOKIE) {
        for entry in header.to_str().ok()?.split(';') {
            let (key, item) = entry.trim().split_once('=')?;
            if key == name {
                if value.is_some() {
                    return None;
                }
                value = Some(item);
            }
        }
    }
    value
}
fn redirect(pending: &Pending, r: &Resource, name: &str, value: &str) -> Result<Response, Fault> {
    redirect_uri(&pending.redirect, pending.state.as_deref(), r, name, value)
}
fn redirect_uri(
    callback: &str,
    state: Option<&str>,
    r: &Resource,
    name: &str,
    value: &str,
) -> Result<Response, Fault> {
    let mut url = Url::parse(callback).map_err(|_| Fault::internal())?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair(name, value).append_pair("iss", &r.issuer);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(url.as_str()).map_err(|_| Fault::internal())?,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}=; Path=/mcp/oauth/authorize; HttpOnly; SameSite=Lax; Max-Age=0{}",
            cookie_name(r),
            if r.secure { "; Secure" } else { "" }
        ))
        .map_err(|_| Fault::internal())?,
    );
    Ok(finish(response, false))
}
pub(super) async fn authorize_post(State(oauth): State<OAuth>, request: Request) -> Response {
    let result = async {
        let r = resource(&oauth, request.headers())?;
        limited(&oauth, &r, "login", 60)?;
        if one_header(request.headers(), header::ORIGIN.as_str()) != Some(r.origin.as_str()) {
            return Err(Fault(
                StatusCode::FORBIDDEN,
                "invalid_request",
                "Authorization form must be submitted from this server",
            ));
        }
        let (headers, bytes) = body(request, "application/x-www-form-urlencoded").await?;
        let p = params(&bytes)?;
        let csrf = required(&p, "csrf")?;
        if csrf.len() != 43
            || !cookie(&headers, cookie_name(&r)).is_some_and(|value| equal(value, csrf))
        {
            return Err(Fault(
                StatusCode::FORBIDDEN,
                "invalid_request",
                "Authorization form expired; start again",
            ));
        }
        let pending = oauth
            .0
            .runtime
            .lock()
            .map_err(|_| Fault::internal())?
            .pending
            .remove(&digest(csrf.as_bytes()))
            .ok_or(Fault::invalid("Authorization form expired; start again"))?;
        if pending.expires <= now() || pending.resource != r.resource {
            return Err(Fault::invalid("Authorization form expired; start again"));
        }
        match required(&p, "decision")? {
            "deny" => return redirect(&pending, &r, "error", "access_denied"),
            "allow" => (),
            _ => return Err(Fault::invalid("Choose allow or deny")),
        }
        if !bool::from(
            required(&p, "owner_token")?
                .as_bytes()
                .ct_eq(&oauth.0.owner),
        ) {
            return Err(Fault(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "Incorrect owner token; start the connection again",
            ));
        }
        let code = secret().map_err(|_| Fault::internal())?;
        oauth
            .transact(|disk| {
                if disk.codes.len() >= MAX_PENDING {
                    bail!("authorization code capacity exceeded");
                }
                let client = disk
                    .clients
                    .get_mut(&pending.client)
                    .context("client no longer registered")?;
                client.used = true;
                disk.codes.insert(
                    digest(code.as_bytes()),
                    Code {
                        client: pending.client.clone(),
                        redirect: pending.redirect.clone(),
                        resource: pending.resource.clone(),
                        scope: pending.scope.clone(),
                        challenge: pending.challenge.clone(),
                        expires: now() + CODE_TTL,
                        grant: None,
                    },
                );
                Ok(())
            })
            .map_err(|_| Fault::internal())?;
        redirect(&pending, &r, "code", &code)
    }
    .await;
    result.unwrap_or_else(Fault::response)
}
pub(super) async fn token(State(oauth): State<OAuth>, request: Request) -> Response {
    exchange::token(oauth, request).await
}
pub(super) async fn revoke(State(oauth): State<OAuth>, request: Request) -> Response {
    exchange::revoke(oauth, request).await
}
