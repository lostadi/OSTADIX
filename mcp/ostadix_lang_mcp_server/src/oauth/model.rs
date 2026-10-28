//! Durable OAuth state and atomic commit boundary.
use super::*;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Client {
    pub name: String,
    pub redirects: Vec<String>,
    pub auth_method: String,
    pub secret_hash: Option<String>,
    pub resource: String,
    pub created: u64,
    pub used: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    pub client: String,
    pub resource: String,
    pub scope: String,
    pub expires: u64,
    pub revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Access {
    pub grant: String,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Refresh {
    pub grant: String,
    pub expires: u64,
    pub used: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Code {
    pub client: String,
    pub redirect: String,
    pub resource: String,
    pub scope: String,
    pub challenge: String,
    pub expires: u64,
    pub grant: Option<String>,
}
#[derive(Clone)]
pub(super) struct Pending {
    pub client: String,
    pub redirect: String,
    pub resource: String,
    pub scope: String,
    pub challenge: String,
    pub state: Option<String>,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Disk {
    pub version: u32,
    pub clients: BTreeMap<String, Client>,
    pub grants: BTreeMap<String, Grant>,
    pub access: BTreeMap<String, Access>,
    pub refresh: BTreeMap<String, Refresh>,
    pub codes: BTreeMap<String, Code>,
}
impl Default for Disk {
    fn default() -> Self {
        Self {
            version: 1,
            clients: BTreeMap::new(),
            grants: BTreeMap::new(),
            access: BTreeMap::new(),
            refresh: BTreeMap::new(),
            codes: BTreeMap::new(),
        }
    }
}
pub(super) struct Runtime {
    pub disk: Disk,
    pub pending: BTreeMap<String, Pending>,
    pub rates: BTreeMap<(String, &'static str), (u64, u32)>,
}
impl Disk {
    pub fn prune(&mut self, now: u64) {
        self.codes.retain(|_, code| code.expires > now);
        self.grants.retain(|_, grant| grant.expires > now);
        self.access
            .retain(|_, token| token.expires > now && self.grants.contains_key(&token.grant));
        // Retain used refresh digests for the entire family lifetime to detect replay.
        self.refresh
            .retain(|_, token| token.expires > now && self.grants.contains_key(&token.grant));
        self.clients.retain(|id, client| {
            client.used
                || client.created.saturating_add(7 * 86400) > now
                || self.grants.values().any(|grant| &grant.client == id)
        });
    }
    pub fn validate(&self, resources: &BTreeMap<String, Resource>) -> anyhow::Result<()> {
        if self.version != 1
            || self.clients.len() > MAX_CLIENTS
            || self.grants.len() > MAX_GRANTS
            || self.access.len() > MAX_TOKENS
            || self.refresh.len() > MAX_TOKENS
            || self.codes.len() > MAX_PENDING
        {
            bail!("OAuth state has unsupported format or exceeds limits");
        }
        let known = |resource: &str| resources.values().any(|value| value.resource == resource);
        for client in self.clients.values() {
            if client.redirects.is_empty()
                || client.redirects.len() > 16
                || !known(&client.resource)
                || !matches!(
                    client.auth_method.as_str(),
                    "none" | "client_secret_post" | "client_secret_basic"
                )
                || (client.auth_method == "none") != client.secret_hash.is_none()
            {
                bail!("invalid persisted OAuth client");
            }
            for redirect in &client.redirects {
                safe_url(redirect)?;
            }
        }
        for grant in self.grants.values() {
            if !self.clients.contains_key(&grant.client)
                || !known(&grant.resource)
                || normalize_scope(&grant.scope).is_none()
            {
                bail!("invalid persisted OAuth grant");
            }
        }
        for token in self.access.values() {
            if !self.grants.contains_key(&token.grant) {
                bail!("orphan OAuth access token");
            }
        }
        for token in self.refresh.values() {
            if !self.grants.contains_key(&token.grant) {
                bail!("orphan OAuth refresh token");
            }
        }
        Ok(())
    }
}

pub(super) fn open_private_state(path: &Path) -> anyhow::Result<File> {
    if !path.is_absolute() {
        bail!("OAuth state directory must be absolute and outside releases");
    }
    if !path.exists() {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("OAuth state directory must not be a symlink");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
        bail!("OAuth state directory must be owned by this user with mode 700");
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lock = options.open(path.join("state.lock"))?;
    check_private_file(&lock)?;
    #[cfg(unix)]
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("OAuth state is already in use by another process");
    }
    Ok(lock)
}
fn check_private_file(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("OAuth state must be a regular file");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        bail!("OAuth state files must be private, owned, and not hard-linked");
    }
    Ok(())
}
pub(super) fn load(path: &Path) -> anyhow::Result<Disk> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = match options.open(path.join("state.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Disk::default()),
        Err(error) => return Err(error.into()),
    };
    check_private_file(&file)?;
    if file.metadata()?.len() > 32 * 1024 * 1024 {
        bail!("OAuth state file exceeds limit");
    }
    let mut bytes = Vec::new();
    file.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        bail!("OAuth state file exceeds limit");
    }
    serde_json::from_slice(&bytes).context("read durable OAuth state")
}
pub(super) fn save(path: &Path, disk: &Disk) -> anyhow::Result<()> {
    let destination = path.join("state.json");
    let temporary = path.join(format!(".state-{}.tmp", secret()?));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&temporary)?;
        serde_json::to_writer(&mut file, disk)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(path)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
