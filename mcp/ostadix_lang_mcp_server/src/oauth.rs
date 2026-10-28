//! A single-owner OAuth authorization server for remote MCP clients.
//!
//! Issuers/resources come only from operator configuration. Client metadata is
//! never fetched from arbitrary URLs. All credentials are opaque random values;
//! only SHA-256 digests are persisted. A failed state write disables token use
//! until restart, so an acknowledged revocation can never survive only in RAM.
mod handlers;
mod model;
#[cfg(test)]
mod tests;

use anyhow::{bail, Context};
use axum::{
    http::{header, HeaderMap, HeaderValue},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use model::{Disk, Pending, Runtime};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use url::Url;

const SCOPE: &str = "ostadix:execute";
const ACCESS_TTL: u64 = 3600;
const FAMILY_TTL: u64 = 30 * 86400;
const CODE_TTL: u64 = 300;
const MAX_CLIENTS: usize = 1024;
const MAX_GRANTS: usize = 4096;
const MAX_TOKENS: usize = 65536;
const MAX_PENDING: usize = 256;
const MAX_BODY: usize = 16 * 1024;

#[derive(Clone)]
pub struct OAuth(Arc<Inner>);

struct Inner {
    resources: BTreeMap<String, Resource>,
    owner: Arc<[u8]>,
    state_dir: PathBuf,
    runtime: Mutex<Runtime>,
    failed: AtomicBool,
    _lock: File,
}

#[derive(Clone, Debug)]
struct Resource {
    resource: String,
    origin: String,
    issuer: String,
    secure: bool,
}

impl OAuth {
    pub fn open(
        public_urls: &[String],
        state_dir: &Path,
        owner_token: Arc<[u8]>,
    ) -> anyhow::Result<Self> {
        if public_urls.is_empty() || owner_token.len() < 32 {
            bail!("OAuth needs public URLs and an owner token of at least 32 bytes");
        }
        let mut resources = BTreeMap::new();
        for raw in public_urls {
            let url = safe_url(raw).context("invalid OAuth public URL")?;
            if url.path() != "/mcp" || url.query().is_some() {
                bail!("OAuth public URL must have exactly /mcp and no query");
            }
            let origin = url.origin().ascii_serialization();
            let authority = &origin[origin.find("://").expect("HTTP origin") + 3..];
            let resource = Resource {
                resource: url.to_string(),
                issuer: format!("{origin}/mcp/oauth"),
                secure: url.scheme() == "https",
                origin: origin.clone(),
            };
            if resources.insert(authority.to_owned(), resource).is_some() {
                bail!("duplicate OAuth public Host authority");
            }
        }
        let lock = model::open_private_state(state_dir)?;
        let mut disk = model::load(state_dir)?;
        disk.prune(now());
        disk.validate(&resources)?;
        let oauth = Self(Arc::new(Inner {
            resources,
            owner: owner_token,
            state_dir: state_dir.to_owned(),
            runtime: Mutex::new(Runtime {
                disk,
                pending: BTreeMap::new(),
                rates: BTreeMap::new(),
            }),
            failed: AtomicBool::new(false),
            _lock: lock,
        }));
        // Prove persistence is usable before advertising OAuth or accepting tokens.
        oauth.transact(|_| Ok(()))?;
        Ok(oauth)
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(handlers::resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource",
                get(handlers::resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server/mcp/oauth",
                get(handlers::server_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(handlers::server_metadata),
            )
            .route(
                "/mcp/oauth/authorize",
                get(handlers::authorize_get).post(handlers::authorize_post),
            )
            .route(
                "/mcp/oauth/register",
                post(handlers::register).options(handlers::preflight),
            )
            .route(
                "/mcp/oauth/token",
                post(handlers::token).options(handlers::preflight),
            )
            .route(
                "/mcp/oauth/revoke",
                post(handlers::revoke).options(handlers::preflight),
            )
            .with_state(self.clone())
    }

    /// A stable grant identity; refreshing a token does not change session owner.
    pub fn authenticate(&self, headers: &HeaderMap) -> Option<String> {
        if self.0.failed.load(Ordering::Acquire) {
            return None;
        }
        let resource = self.resource(headers)?;
        let auth = one_header(headers, header::AUTHORIZATION.as_str())?;
        let (scheme, token) = auth.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") || token.len() > 256 {
            return None;
        }
        let runtime = self.0.runtime.lock().ok()?;
        // A preceding writer may have failed while this reader waited.
        if self.0.failed.load(Ordering::Acquire) {
            return None;
        }
        let access = runtime.disk.access.get(&digest(token.as_bytes()))?;
        let grant = runtime.disk.grants.get(&access.grant)?;
        let now = now();
        (!grant.revoked
            && access.expires > now
            && grant.expires > now
            && grant.resource == resource.resource
            && normalize_scope(&grant.scope).is_some())
        .then(|| access.grant.clone())
    }

    pub fn challenge(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        let resource = self.resource(headers)?;
        HeaderValue::from_str(&format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\"",
            resource.origin)).ok()
    }

    fn resource(&self, headers: &HeaderMap) -> Option<&Resource> {
        self.0
            .resources
            .get(one_header(headers, header::HOST.as_str())?)
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut Disk) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if self.0.failed.load(Ordering::Acquire) {
            bail!("OAuth persistence is unavailable");
        }
        let mut runtime = self
            .0
            .runtime
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth state poisoned"))?;
        if self.0.failed.load(Ordering::Acquire) {
            bail!("OAuth persistence is unavailable");
        }
        let mut candidate = runtime.disk.clone();
        candidate.prune(now());
        let result = operation(&mut candidate)?;
        if let Err(error) = model::save(&self.0.state_dir, &candidate) {
            self.0.failed.store(true, Ordering::Release);
            return Err(error);
        }
        runtime.disk = candidate;
        Ok(result)
    }

    /// A bounded, global per-resource limiter avoids trusting forwarded IPs.
    fn rate(&self, resource: &Resource, operation: &'static str, limit: u32) -> bool {
        let Ok(mut runtime) = self.0.runtime.lock() else {
            return false;
        };
        let now = now();
        let rate = runtime
            .rates
            .entry((resource.resource.clone(), operation))
            .or_insert((now, 0));
        if now.saturating_sub(rate.0) >= 3600 {
            *rate = (now, 0);
        }
        if rate.1 >= limit {
            return false;
        }
        rate.1 += 1;
        true
    }

    fn put_pending(&self, nonce: &str, pending: Pending) -> anyhow::Result<()> {
        let mut runtime = self
            .0
            .runtime
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth state poisoned"))?;
        runtime.pending.retain(|_, p| p.expires > now());
        if runtime.pending.len() >= MAX_PENDING {
            bail!("too many pending authorizations");
        }
        runtime.pending.insert(digest(nonce.as_bytes()), pending);
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn digest(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value))
}
fn secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn equal(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn one_header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    let mut values = headers.get_all(key).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
fn safe_url(raw: &str) -> anyhow::Result<Url> {
    if raw.len() > 2048
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        bail!("invalid URL");
    }
    let url = Url::parse(raw)?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host().is_none()
    {
        bail!("URL requires HTTPS (or HTTP loopback), without credentials or fragment");
    }
    Ok(url)
}

fn normalize_scope(scope: &str) -> Option<String> {
    let values: Vec<_> = scope.split(' ').collect();
    match values.as_slice() {
        ["ostadix:execute"] => Some(SCOPE.to_owned()),
        ["ostadix:execute", "offline_access"] | ["offline_access", "ostadix:execute"] => {
            Some(format!("{SCOPE} offline_access"))
        }
        _ => None,
    }
}

/// RFC 8252 loopback listeners may choose an ephemeral port. Everything else
/// remains exact, and the resulting code binds the actual requested URI.
fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(mut registered), Ok(mut requested)) = (safe_url(registered), safe_url(requested))
    else {
        return false;
    };
    if registered.scheme() != "http" || requested.scheme() != "http" {
        return false;
    }
    // safe_url admits HTTP only on loopback, including native localhost clients.
    if registered.set_port(None).is_err() || requested.set_port(None).is_err() {
        return false;
    }
    registered == requested
}
