//! Remote MCP transport. The SDK owns JSON-RPC, SSE, and session negotiation;
//! this module owns listener configuration, access policy, and process shutdown.

use crate::{execution::WeakJobManager, oauth::OAuth, OstadixMcp, RuntimeSearchPath};
use anyhow::{bail, Context};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::{Parser, ValueEnum};
use rmcp::transport::streamable_http_server::{
    session::{local::LocalSessionManager, SessionManager},
    StreamableHttpServerConfig, StreamableHttpService,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    #[default]
    Stdio,
    Http,
}

#[derive(Parser)]
#[command(
    version,
    about = "Ostadix MCP: local stdio or remote Streamable HTTP at /mcp"
)]
pub struct Options {
    #[arg(long, value_enum, default_value = "stdio")]
    pub transport: Transport,
    /// HTTP listening address. Put TLS at a reverse proxy for remote clients.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    /// File containing the bearer token (or set OSTADIX_MCP_BEARER_TOKEN).
    #[arg(long, conflicts_with = "allow_unauthenticated")]
    token_file: Option<PathBuf>,
    /// Enable OAuth at this exact public MCP URL; repeat for public aliases.
    #[arg(
        long,
        requires = "oauth_state_dir",
        conflicts_with = "allow_unauthenticated"
    )]
    oauth_public_url: Vec<String>,
    /// Absolute private directory for OAuth grants, outside managed releases.
    #[arg(long, requires = "oauth_public_url")]
    oauth_state_dir: Option<PathBuf>,
    /// Explicitly disable bearer authentication, e.g. behind an auth gateway.
    #[arg(long)]
    allow_unauthenticated: bool,
    /// Additional accepted Host authority; repeat for multiple public names.
    #[arg(long)]
    allowed_host: Vec<String>,
    /// Accepted browser origin including scheme and port; repeat as needed.
    #[arg(long)]
    allowed_origin: Vec<String>,
    /// Session inactivity expiry; zero disables expiry for long-running jobs.
    #[arg(long, default_value_t = 3600)]
    session_timeout_secs: u64,
    /// Maximum complete MCP request size, including inline source.
    #[arg(long, default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(usize))]
    max_request_bytes: usize,
}

#[derive(Clone)]
struct Access {
    token: Option<Arc<[u8]>>,
    oauth: Option<OAuth>,
    session_owners: Arc<Mutex<HashMap<String, String>>>,
    sessions: Arc<LocalSessionManager>,
    origins: Vec<HeaderValue>,
    max_request_bytes: usize,
    stopping: CancellationToken,
}

fn load_token(options: &Options) -> anyhow::Result<Option<Arc<[u8]>>> {
    let environment = std::env::var("OSTADIX_MCP_BEARER_TOKEN").ok();
    if options.allow_unauthenticated {
        if environment.is_some() {
            bail!("unset OSTADIX_MCP_BEARER_TOKEN before using --allow-unauthenticated");
        }
        return Ok(None);
    }
    let token = if let Some(path) = &options.token_file {
        if environment.is_some() {
            bail!("choose --token-file or OSTADIX_MCP_BEARER_TOKEN, not both");
        }
        std::fs::read_to_string(path).context("read MCP bearer token file")?
    } else {
        environment.context("HTTP requires --token-file or OSTADIX_MCP_BEARER_TOKEN; use --allow-unauthenticated explicitly for an unauthenticated endpoint")?
    };
    let token = token.trim();
    if token.len() < 32 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        bail!(
            "MCP bearer token must contain at least 32 printable ASCII characters without spaces"
        );
    }
    Ok(Some(Arc::from(token.as_bytes())))
}

fn authorized(headers: &axum::http::HeaderMap, expected: Option<&[u8]>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    // Reject duplicate Authorization fields instead of choosing one arbitrarily.
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Bearer") && bool::from(token.as_bytes().ct_eq(expected))
}

fn supported_header(headers: &axum::http::HeaderMap) -> bool {
    headers.get("mcp-protocol-version").is_none_or(|value| {
        matches!(
            value.to_str(),
            Ok("2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25")
        )
    })
}

fn allowed_origin(headers: &axum::http::HeaderMap, allowed: &[HeaderValue]) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    match values.next() {
        None => true,
        Some(origin) => values.next().is_none() && allowed.contains(origin),
    }
}

async fn access(State(access): State<Access>, request: Request, next: Next) -> Response {
    if access.stopping.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "MCP server is stopping").into_response();
    }
    let principal = if authorized(request.headers(), access.token.as_deref()) {
        Some("owner".to_owned())
    } else {
        access
            .oauth
            .as_ref()
            .and_then(|oauth| oauth.authenticate(request.headers()))
    };
    let Some(principal) = principal else {
        let challenge = access
            .oauth
            .as_ref()
            .and_then(|oauth| oauth.challenge(request.headers()))
            .unwrap_or_else(|| HeaderValue::from_static("Bearer realm=\"ostadix-mcp\""));
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, challenge)],
            "MCP bearer token required",
        )
            .into_response();
    };
    // Match CORS exactly. The SDK currently treats a portless allowlist entry
    // as matching any port, which would otherwise admit unintended origins.
    if !allowed_origin(request.headers(), &access.origins) {
        return (StatusCode::FORBIDDEN, "Origin is not allowed").into_response();
    }
    // An OAuth grant may retain its own sessions across refresh, but cannot
    // adopt another app's jobs or intent handles using a leaked session ID.
    let session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if access.oauth.is_some() {
        if let Some(id) = &session_id {
            let owners = access
                .session_owners
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if owners.get(id) != Some(&principal) {
                return (StatusCode::NOT_FOUND, "MCP session not found").into_response();
            }
        }
    }
    let deleting = request.method() == Method::DELETE;
    let mut request = request;
    if request.method() == Method::POST {
        let (parts, body) = request.into_parts();
        let body_result = tokio::select! {
            result = to_bytes(body, access.max_request_bytes) => result,
            _ = access.stopping.cancelled() => {
                return (StatusCode::SERVICE_UNAVAILABLE, "MCP server is stopping").into_response();
            }
        };
        let bytes = match body_result {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "MCP request exceeds --max-request-bytes",
                )
                    .into_response()
            }
        };
        // Ostadix's jobs and intent leases are session-owned. Prevent the SDK's
        // newer sessionless route from constructing ephemeral state per call.
        // An initialize asking for a newer revision may still negotiate down.
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Expected a JSON MCP message").into_response()
            }
        };
        if value.get("method").and_then(|m| m.as_str()) != Some("initialize") {
            let inline_version =
                value.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion");
            if !supported_header(&parts.headers) || inline_version.is_some() {
                return (StatusCode::BAD_REQUEST, "Use initialize and the negotiated session protocol (through 2025-11-25); sessionless MCP is not supported").into_response();
            }
        }
        request = Request::from_parts(parts, Body::from(bytes));
    } else if !supported_header(request.headers()) {
        return (StatusCode::BAD_REQUEST, "Unsupported MCP protocol version").into_response();
    }
    let response = next.run(request).await;
    if access.oauth.is_some() && response.status().is_success() {
        let active = access.sessions.sessions.read().await;
        let mut owners = access
            .session_owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        owners.retain(|id, _| active.contains_key(id.as_str()));
        if deleting {
            if let Some(id) = session_id {
                owners.remove(&id);
            }
        } else if let Some(id) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            owners.insert(id.to_owned(), principal);
        }
    }
    response
}

pub async fn serve(options: Options, runtime_search: RuntimeSearchPath) -> anyhow::Result<()> {
    let token = load_token(&options)?;
    let oauth = options
        .oauth_state_dir
        .as_ref()
        .map(|state_dir| {
            OAuth::open(
                &options.oauth_public_url,
                state_dir,
                token
                    .clone()
                    .context("OAuth requires an owner bearer token")?,
            )
        })
        .transpose()?;
    if options.max_request_bytes == 0 {
        bail!("--max-request-bytes must be positive");
    }
    let stopping = CancellationToken::new();
    let jobs: Arc<Mutex<Vec<WeakJobManager>>> = Arc::new(Mutex::new(Vec::new()));
    let mut config = StreamableHttpServerConfig::default().enforce_origin_validation();
    config.cancellation_token = stopping.clone();
    config.max_request_body_bytes = options.max_request_bytes;
    for host in &options.allowed_host {
        if host.is_empty() || host.contains(['/', '*', ' ', '\\']) {
            bail!("--allowed-host must be an exact hostname or host:port");
        }
    }
    config.allowed_hosts.extend(options.allowed_host);
    for public_url in &options.oauth_public_url {
        let uri: axum::http::Uri = public_url.parse().context("invalid OAuth public URL")?;
        config.allowed_hosts.push(
            uri.authority()
                .context("OAuth URL has no authority")?
                .to_string(),
        );
    }
    // Exact origins keep the transport check and CORS policy aligned.
    let origins: Vec<HeaderValue> = options
        .allowed_origin
        .iter()
        .map(|origin| {
            let uri: axum::http::Uri = origin.parse().context("invalid --allowed-origin")?;
            if !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.authority().is_none()
                || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
                || origin.contains(['@', '*'])
                || format!(
                    "{}://{}",
                    uri.scheme_str().unwrap_or(""),
                    uri.authority().map(|a| a.as_str()).unwrap_or("")
                ) != *origin
            {
                bail!("--allowed-origin requires an http(s) origin without a path");
            }
            origin.parse().context("invalid origin header")
        })
        .collect::<anyhow::Result<_>>()?;
    config.allowed_origins = options.allowed_origin;
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = (options.session_timeout_secs != 0)
        .then(|| Duration::from_secs(options.session_timeout_secs));
    let sessions = Arc::new(manager);
    let registry = jobs.clone();
    let factory_stopping = stopping.clone();
    let service = StreamableHttpService::new(
        move || {
            // Serialize creation with shutdown's registry snapshot.
            let mut registry = registry.lock().unwrap_or_else(|e| e.into_inner());
            if factory_stopping.is_cancelled() {
                return Err(std::io::Error::other("MCP server is stopping"));
            }
            let mut server = OstadixMcp::new(runtime_search.clone());
            server.http_mode = true;
            registry.retain(|manager| manager.upgrade().is_some());
            registry.push(server.jobs.downgrade());
            Ok(server)
        },
        sessions.clone(),
        config,
    );
    let cors = CorsLayer::new()
        .allow_origin(origins.clone())
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            "mcp-session-id".parse().unwrap(),
            "mcp-protocol-version".parse().unwrap(),
            "last-event-id".parse().unwrap(),
        ])
        .expose_headers([
            header::WWW_AUTHENTICATE,
            "mcp-session-id".parse().unwrap(),
            "mcp-protocol-version".parse().unwrap(),
        ]);
    let mut app = Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn_with_state(
            Access {
                token,
                oauth: oauth.clone(),
                session_owners: Arc::new(Mutex::new(HashMap::new())),
                sessions: sessions.clone(),
                origins,
                max_request_bytes: options.max_request_bytes,
                stopping: stopping.clone(),
            },
            access,
        ))
        .layer(cors)
        .route("/healthz", get(|| async { "ostadix-mcp ok\n" }));
    if let Some(oauth) = oauth {
        app = app.merge(oauth.router());
    }
    let listener = tokio::net::TcpListener::bind(options.bind)
        .await
        .context("bind MCP HTTP listener")?;
    tracing::info!(
        "Ostadix MCP listening at http://{}/mcp",
        listener.local_addr()?
    );
    if options.allow_unauthenticated {
        tracing::info!("HTTP bearer authentication explicitly disabled");
    }
    let shutdown = async move {
        shutdown_signal().await;
        // Take strong references only during shutdown, after closing creation.
        let managers: Vec<_> = {
            let registry = jobs.lock().unwrap_or_else(|e| e.into_inner());
            let managers = registry
                .iter()
                .filter_map(WeakJobManager::upgrade)
                .collect();
            stopping.cancel();
            managers
        };
        let ids: Vec<_> = sessions.sessions.read().await.keys().cloned().collect();
        for id in ids {
            if let Err(error) = sessions.close_session(&id).await {
                tracing::error!(%error, "HTTP session close failed");
            }
        }
        let mut cleanup = tokio::task::JoinSet::new();
        for manager in managers {
            cleanup.spawn(async move { manager.shutdown().await });
        }
        while let Some(result) = cleanup.join_next().await {
            if let Err(error) = result
                .context("HTTP session shutdown task")
                .and_then(|r| r.map_err(anyhow::Error::msg))
            {
                tracing::error!(%error, "HTTP job cleanup failed");
            }
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_requires_exact_single_bearer_token() {
        let token = b"test-secret-at-least-thirty-two-characters";
        let mut headers = axum::http::HeaderMap::new();
        assert!(!authorized(&headers, Some(token)));
        headers.insert(
            header::AUTHORIZATION,
            "bearer test-secret-at-least-thirty-two-characters"
                .parse()
                .unwrap(),
        );
        assert!(authorized(&headers, Some(token)));
        assert!(!authorized(&headers, Some(b"different")));
        headers.append(header::AUTHORIZATION, "Bearer another".parse().unwrap());
        assert!(!authorized(&headers, Some(token)));
    }

    #[test]
    fn origin_policy_is_exact_including_port_and_rejects_duplicate_headers() {
        let mut headers = axum::http::HeaderMap::new();
        let allowed = vec![HeaderValue::from_static("https://client.example")];
        assert!(allowed_origin(&headers, &allowed));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://client.example:9999"),
        );
        assert!(!allowed_origin(&headers, &allowed));
        headers.insert(header::ORIGIN, allowed[0].clone());
        assert!(allowed_origin(&headers, &allowed));
        headers.append(header::ORIGIN, allowed[0].clone());
        assert!(!allowed_origin(&headers, &allowed));
    }

    #[test]
    fn stdio_remains_the_default_and_http_requires_explicit_selection() {
        let options = Options::try_parse_from(["ostadix-mcp"]).unwrap();
        assert_eq!(options.transport, Transport::Stdio);
        let options = Options::try_parse_from(["ostadix-mcp", "--transport", "http"]).unwrap();
        assert_eq!(options.transport, Transport::Http);
        assert!(options.bind.ip().is_loopback());
    }
}
