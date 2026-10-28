//! Authorization-code exchange, refresh rotation, and family revocation.
use super::*;
use crate::oauth::model::{Access, Grant, Refresh};
use base64::engine::general_purpose::STANDARD;

fn client_credentials(
    headers: &HeaderMap,
    p: &Params,
) -> Result<(String, Option<String>, &'static str), Fault> {
    if headers.contains_key(header::AUTHORIZATION) {
        let auth = one_header(headers, header::AUTHORIZATION.as_str()).ok_or_else(Fault::client)?;
        let (scheme, encoded) = auth.split_once(' ').ok_or_else(Fault::client)?;
        if !scheme.eq_ignore_ascii_case("basic") || p.contains_key("client_secret") {
            return Err(Fault::client());
        }
        let decoded = STANDARD.decode(encoded).map_err(|_| Fault::client())?;
        let decoded = std::str::from_utf8(&decoded).map_err(|_| Fault::client())?;
        let (id, secret) = decoded.split_once(':').ok_or_else(Fault::client)?;
        // OAuth Basic credentials are individually form-encoded before base64.
        let decode = |value: &str| -> Result<String, Fault> {
            let value = params(format!("v={value}").as_bytes())?;
            if value.len() != 1 {
                return Err(Fault::client());
            }
            Ok(required(&value, "v")?.to_owned())
        };
        let id = decode(id)?;
        if p.get("client_id").is_some_and(|value| value != &id) {
            return Err(Fault::client());
        }
        return Ok((id, Some(decode(secret)?), "client_secret_basic"));
    }
    let id = required(p, "client_id")?.to_owned();
    let secret = p.get("client_secret").cloned();
    let method = if secret.is_some() {
        "client_secret_post"
    } else {
        "none"
    };
    Ok((id, secret, method))
}
fn authenticate_client(
    disk: &Disk,
    r: &Resource,
    headers: &HeaderMap,
    p: &Params,
) -> Result<String, Fault> {
    let (id, secret, method) = client_credentials(headers, p)?;
    let client = disk.clients.get(&id).ok_or_else(Fault::client)?;
    if client.resource != r.resource || client.auth_method != method {
        return Err(Fault::client());
    }
    if let Some(expected) = &client.secret_hash {
        if !secret.is_some_and(|value| equal(&digest(value.as_bytes()), expected)) {
            return Err(Fault::client());
        }
    }
    Ok(id)
}
fn issue(disk: &mut Disk, grant_id: &str, expires: u64) -> anyhow::Result<Value> {
    if disk.access.len() >= MAX_TOKENS || disk.refresh.len() >= MAX_TOKENS {
        bail!("token capacity exceeded");
    }
    let access = secret()?;
    let refresh = secret()?;
    let access_expires = (now() + ACCESS_TTL).min(expires);
    disk.access.insert(
        digest(access.as_bytes()),
        Access {
            grant: grant_id.to_owned(),
            expires: access_expires,
        },
    );
    disk.refresh.insert(
        digest(refresh.as_bytes()),
        Refresh {
            grant: grant_id.to_owned(),
            expires,
            used: false,
        },
    );
    Ok(
        json!({"access_token":access,"token_type":"Bearer","expires_in":access_expires.saturating_sub(now()),
        "refresh_token":refresh,"scope":disk.grants[grant_id].scope}),
    )
}
fn exchange_code(
    disk: &mut Disk,
    r: &Resource,
    client: &str,
    p: &Params,
) -> anyhow::Result<Result<Value, Fault>> {
    let hash = digest(
        required(p, "code")
            .map_err(|_| anyhow::anyhow!("missing code"))?
            .as_bytes(),
    );
    let Some(code) = disk.codes.get(&hash).cloned() else {
        return Ok(Err(Fault::grant()));
    };
    let verifier = p.get("code_verifier").map_or("", String::as_str);
    if code.client != client
        || code.resource != r.resource
        || code.expires <= now()
        || p.get("redirect_uri") != Some(&code.redirect)
        || !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        || !equal(&digest(verifier.as_bytes()), &code.challenge)
    {
        return Ok(Err(Fault::grant()));
    }
    if let Some(grant) = code.grant {
        if let Some(grant) = disk.grants.get_mut(&grant) {
            grant.revoked = true;
        }
        return Ok(Err(Fault::grant()));
    }
    if disk.grants.len() >= MAX_GRANTS {
        bail!("grant capacity exceeded");
    }
    let grant = secret()?;
    let expires = now() + FAMILY_TTL;
    disk.grants.insert(
        grant.clone(),
        Grant {
            client: client.to_owned(),
            resource: code.resource,
            scope: code.scope,
            expires,
            revoked: false,
        },
    );
    disk.codes
        .get_mut(&hash)
        .expect("code exists under lock")
        .grant = Some(grant.clone());
    Ok(Ok(issue(disk, &grant, expires)?))
}
fn exchange_refresh(
    disk: &mut Disk,
    r: &Resource,
    client: &str,
    p: &Params,
) -> anyhow::Result<Result<Value, Fault>> {
    let token = p.get("refresh_token").map_or("", String::as_str);
    let hash = digest(token.as_bytes());
    let Some(refresh) = disk.refresh.get(&hash).cloned() else {
        return Ok(Err(Fault::grant()));
    };
    let Some(grant) = disk.grants.get_mut(&refresh.grant) else {
        return Ok(Err(Fault::grant()));
    };
    if grant.client != client
        || grant.resource != r.resource
        || grant.expires <= now()
        || refresh.expires <= now()
    {
        return Ok(Err(Fault::grant()));
    }
    if refresh.used {
        grant.revoked = true;
        return Ok(Err(Fault::grant()));
    }
    if grant.revoked {
        return Ok(Err(Fault::grant()));
    }
    if p.get("scope")
        .is_some_and(|scope| normalize_scope(scope).as_ref() != Some(&grant.scope))
    {
        return Ok(Err(Fault(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Refresh cannot change the granted scope",
        )));
    }
    let expires = grant.expires;
    disk.refresh
        .get_mut(&hash)
        .expect("refresh exists under lock")
        .used = true;
    Ok(Ok(issue(disk, &refresh.grant, expires)?))
}
pub(super) async fn token(oauth: OAuth, request: Request) -> Response {
    let result = async {
        let r = resource(&oauth, request.headers())?;
        limited(&oauth, &r, "token", 3600)?;
        let (headers, bytes) = body(request, "application/x-www-form-urlencoded").await?;
        let p = params(&bytes)?;
        if required(&p, "resource")? != r.resource {
            return Err(Fault(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "Resource must exactly match this MCP URL",
            ));
        }
        let grant_type = required(&p, "grant_type")?;
        match grant_type {
            "authorization_code" => {
                required(&p, "code")?;
                required(&p, "redirect_uri")?;
                required(&p, "code_verifier")?;
            }
            "refresh_token" => {
                required(&p, "refresh_token")?;
            }
            _ => {
                return Err(Fault(
                    StatusCode::BAD_REQUEST,
                    "unsupported_grant_type",
                    "Use authorization_code or refresh_token",
                ))
            }
        }
        let issued = oauth
            .transact(|disk| {
                let client = match authenticate_client(disk, &r, &headers, &p) {
                    Ok(client) => client,
                    Err(error) => return Ok(Err(error)),
                };
                if grant_type == "authorization_code" {
                    exchange_code(disk, &r, &client, &p)
                } else {
                    exchange_refresh(disk, &r, &client, &p)
                }
            })
            .map_err(|_| Fault::internal())??;
        Ok(finish(Json(issued).into_response(), true))
    }
    .await;
    result.unwrap_or_else(Fault::response)
}
pub(super) async fn revoke(oauth: OAuth, request: Request) -> Response {
    let result = async {
        let r = resource(&oauth, request.headers())?;
        limited(&oauth, &r, "revoke", 3600)?;
        let (headers, bytes) = body(request, "application/x-www-form-urlencoded").await?;
        let p = params(&bytes)?;
        let hash = digest(required(&p, "token")?.as_bytes());
        oauth
            .transact(|disk| {
                let client = match authenticate_client(disk, &r, &headers, &p) {
                    Ok(client) => client,
                    Err(error) => return Ok(Err(error)),
                };
                let grant = disk
                    .refresh
                    .get(&hash)
                    .map(|token| token.grant.clone())
                    .or_else(|| disk.access.get(&hash).map(|token| token.grant.clone()));
                if let Some(grant) = grant.and_then(|id| disk.grants.get_mut(&id)) {
                    if grant.client == client && grant.resource == r.resource {
                        grant.revoked = true;
                    }
                }
                Ok(Ok(()))
            })
            .map_err(|_| Fault::internal())??;
        Ok(finish(StatusCode::OK.into_response(), true))
    }
    .await;
    result.unwrap_or_else(Fault::response)
}
