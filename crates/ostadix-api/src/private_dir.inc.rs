// shared with generated project runtimes, which copy this file next to their
// own `shims` module; it names every item by full path so it needs no imports.

// ### private shim dir ###
// a fixed or guessable name under a shared /tmp lets another user plant a
// symlink or swap an adapter before it runs. the name is random, create (not
// create_dir_all) refuses any existing path, symlinks included, and 0700 keeps
// other users out.

/// Create a fresh private directory `<temp>/<prefix><sep><pid><sep><random>`.
/// callers pick the separator because some names are matched by globs that
/// users already wrote, e.g. a project workspace under `*/olang-ws-*`.
pub fn create_private_dir_with_separator(
    prefix: &str,
    separator: char,
) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context as _;
    let base = std::env::temp_dir();
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = base.join(format!(
            "{prefix}{separator}{}{separator}{}",
            std::process::id(),
            hex::encode(random)
        ));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            // only reuse or a planted name collides; draw another.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create private directory {}", dir.display()))
            }
        }
    }
    anyhow::bail!("no free private directory name under {}", base.display())
}
