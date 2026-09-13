//! Explicit browser-only Guix packaging. This builds assets, never runs Guix.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PROXY_URL: &str =
    "https://github.com/container2wasm/container2wasm/releases/download/v0.8.4/c2w-net-proxy.wasm";
const PROXY_SHA: &str = "2156167ecd413d1b7a0f5cf404e4a99967a9ae37c96161621ebb9f0b15d97638";
const PROXY_BYTES: u64 = 21_574_298;
const DISK_DOCKERFILE: &str = include_str!("browser_guix/Dockerfile");
const DISK_GENERATOR: &str = include_str!("browser_guix/create_disk.py");

pub fn state_profile(runtime_image: &str) -> serde_json::Value {
    let hash = Sha256::digest(runtime_image.as_bytes());
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&hash[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let h = hex::encode(uuid);
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    );
    serde_json::json!({"schema":"ostadix.guix-state/v1", "uuid":uuid,
        "bytes":2_147_483_648_u64, "runtime_image":runtime_image, "layout":1})
}

fn write_owned(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file.write_all(bytes).context("write Guix build asset"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)?.is_file() || fs::read(path)? != bytes {
                bail!(
                    "refusing to replace different Guix asset {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub fn materialize_assets(build_dir: &Path, runtime_image: &str) -> Result<()> {
    let directory = build_dir.join("guix-assets-build");
    if !directory.exists() {
        fs::create_dir(&directory)?;
    }
    if !fs::symlink_metadata(&directory)?.is_dir() {
        bail!("Guix asset build directory is not a directory");
    }
    write_owned(&directory.join("Dockerfile"), DISK_DOCKERFILE.as_bytes())?;
    write_owned(&directory.join("create_disk.py"), DISK_GENERATOR.as_bytes())?;
    write_owned(
        &directory.join("state-profile.json"),
        &serde_json::to_vec_pretty(&state_profile(runtime_image))?,
    )?;
    write_owned(
        &directory.join(".dockerignore"),
        b"**\n!Dockerfile\n!create_disk.py\n!state-profile.json\n",
    )
}

fn run(command: &mut Command, description: &str) -> Result<()> {
    let status = command
        .stdin(Stdio::null())
        .status()
        .with_context(|| description.to_string())?;
    if !status.success() {
        bail!("{description} failed: {status}");
    }
    Ok(())
}

pub fn build_assets(build_dir: &Path, runtime_image: &str) -> Result<()> {
    materialize_assets(build_dir, runtime_image)?;
    let output = build_dir.join("guix-browser-assets");
    fs::create_dir(&output).context("create new Guix browser assets output")?;
    let output_arg = output.to_str().context("Guix asset output must be UTF-8")?;
    if output_arg.contains([',', '\n', '\r']) {
        bail!("unsafe Buildx output path");
    }
    run(
        Command::new("docker")
            .args(["buildx", "build", "--target", "export", "--output"])
            .arg(format!("type=local,dest={output_arg}"))
            .arg(build_dir.join("guix-assets-build")),
        "build fresh sparse Guix disk assets",
    )?;
    // This immutable release module is the network stack, not a remote helper.
    // The resulting bundle contains it and never fetches executable code on boot.
    let proxy = output.join("c2w-net-proxy.wasm");
    run(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "300",
                "--max-filesize",
                "21574298",
                "--output",
            ])
            .arg(&proxy)
            .arg(PROXY_URL),
        "acquire pinned in-browser network module",
    )?;
    let bytes = fs::read(&proxy)?;
    if bytes.len() as u64 != PROXY_BYTES || super::sha256_hex(&bytes) != PROXY_SHA {
        bail!("network module does not match its pinned release digest and size");
    }
    Ok(())
}

/// Called only on a just-created, invocation-owned Linux bundle. Its original
/// plan/build/adapter consistency checks have already completed in the writer.
pub fn finish_bundle(bundle: &Path, build_dir: &Path, runtime_image: &str) -> Result<()> {
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("manifest.json"))?)?;
    let build: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("wasm-build.json"))?)?;
    if build["browser_guix_state"] != state_profile(runtime_image)
        || build["converter"]["browser_guix"] != true
    {
        bail!("Guix state profile is not bound to the converter build");
    }
    let output = build_dir.join("guix-browser-assets");
    let proxy = fs::read(output.join("c2w-net-proxy.wasm"))?;
    if proxy.len() as u64 != PROXY_BYTES || super::sha256_hex(&proxy) != PROXY_SHA {
        bail!("network proxy integrity mismatch");
    }
    let disk_bytes = fs::read(output.join("initial-disk.json"))?;
    let disk: serde_json::Value = serde_json::from_slice(&disk_bytes)?;
    if disk["schema"] != "ostadix.sparse-disk/v1"
        || disk["bytes"] != 2_147_483_648_u64
        || disk["block_bytes"] != 4096
    {
        bail!("invalid initial disk asset");
    }
    let chunks = disk["chunks"]
        .as_array()
        .context("initial disk has no chunk list")?;
    if chunks.len() > 4096 {
        bail!("too many initial disk chunks");
    }
    let mut end = 0_u64;
    let mut total = 0_u64;
    fs::create_dir(bundle.join("disk-chunks"))?;
    for (index, chunk) in chunks.iter().enumerate() {
        let path = format!("disk-chunks/{index:04}.bin");
        if chunk["path"] != path {
            bail!("noncanonical disk chunk path");
        }
        let offset = chunk["offset"].as_u64().context("invalid disk offset")?;
        let size = chunk["bytes"].as_u64().context("invalid disk chunk size")?;
        if offset < end
            || offset % 4096 != 0
            || size == 0
            || size > 1_048_576
            || offset
                .checked_add(size)
                .is_none_or(|value| value > 2_147_483_648)
        {
            bail!("invalid initial disk extent");
        }
        total += size;
        if total > 67_108_864 {
            bail!("initial disk metadata exceeds 64 MiB");
        }
        end = offset + size;
        let bytes = fs::read(output.join(&path))?;
        if bytes.len() as u64 != size || chunk["sha256"] != super::sha256_hex(&bytes) {
            bail!("disk chunk integrity mismatch");
        }
        super::write_new_browser_file(&bundle.join(path), &bytes)?;
    }
    let mut assets = BTreeMap::<String, Vec<u8>>::new();
    macro_rules! asset {
        ($name:literal, $file:literal) => {
            assets.insert($name.into(), include_bytes!($file).to_vec());
        };
    }
    asset!(
        "browser-main.mjs",
        "../../../apps/olang-browser-wasi/guix-browser-main.mjs"
    );
    asset!(
        "index.html",
        "../../../apps/olang-browser-wasi/guix-index.html"
    );
    asset!(
        "browser-disk-wasi.mjs",
        "../../../apps/olang-browser-wasi/browser-disk-wasi.mjs"
    );
    asset!(
        "guix-browser-state.mjs",
        "../../../apps/olang-browser-wasi/guix-browser-state.mjs"
    );
    asset!(
        "guix-mirror-fetch-broker.mjs",
        "../../../apps/olang-browser-wasi/guix-mirror-fetch-broker.mjs"
    );
    asset!(
        "guix-network-transport.mjs",
        "../../../apps/olang-browser-wasi/guix-network-transport.mjs"
    );
    asset!(
        "guix-network-guest-host.mjs",
        "../../../apps/olang-browser-wasi/guix-network-guest-host.mjs"
    );
    asset!(
        "guix-network-proxy-host.mjs",
        "../../../apps/olang-browser-wasi/guix-network-proxy-host.mjs"
    );
    asset!(
        "guix-network-proxy-worker.mjs",
        "../../../apps/olang-browser-wasi/guix-network-proxy-worker.mjs"
    );
    asset!(
        "guix-session-runner.mjs",
        "../../../apps/olang-browser-wasi/guix-session-runner.mjs"
    );
    asset!(
        "guix-session-worker.mjs",
        "../../../apps/olang-browser-wasi/guix-session-worker.mjs"
    );
    asset!(
        "interactive-linux-wasi-host.mjs",
        "../../../apps/olang-browser-wasi/interactive-linux-wasi-host.mjs"
    );
    asset!(
        "linux-wasi-host.mjs",
        "../../../apps/olang-browser-wasi/linux-wasi-host.mjs"
    );
    asset!("runner.mjs", "../../../apps/olang-browser-wasi/runner.mjs");
    asset!(
        "wasi-preview1-host.mjs",
        "../../../apps/olang-browser-wasi/wasi-preview1-host.mjs"
    );
    assets.insert("c2w-net-proxy.wasm".into(), proxy);
    assets.insert("initial-disk.json".into(), disk_bytes);
    assets.insert(
        "state-profile.json".into(),
        serde_json::to_vec_pretty(&state_profile(runtime_image))?,
    );
    let records = assets
        .iter()
        .map(|(path, bytes)| super::browser_bundle_file(path, bytes))
        .collect::<Vec<_>>();
    for (path, bytes) in &assets {
        fs::write(bundle.join(path), bytes)?;
    }
    // Remove only obsolete assets written by the preceding owned writer.
    for path in ["linux-runner.mjs", "linux-worker.mjs"] {
        fs::remove_file(bundle.join(path))?;
    }
    manifest["schema"] = "ostadix.olang-guix-browser-bundle/v1".into();
    manifest["assets"] = serde_json::to_value(records)?;
    manifest["abi"]["local_capabilities"] = serde_json::json!([
        "args",
        "environment",
        "clock-realtime",
        "clock-monotonic",
        "queued-stdin",
        "streamed-stdout",
        "streamed-stderr",
        "embedded-linux-filesystem",
        "embedded-linux-processes",
        "origin-private-guix-disk",
        "guix-mirror-fetch"
    ]);
    manifest["abi"]["denied_capabilities"] = serde_json::json!([
        "host-filesystem-paths",
        "host-process-spawn",
        "arbitrary-network",
        "local-helper"
    ]);
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
