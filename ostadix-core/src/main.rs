use regex::Regex;
use std::env;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

// The injector shell script is baked directly into the binary at compile time.
// No loose files needed on the host system.
const INJECTOR_SH: &str = include_str!("injector.sh");

// The Lisp module-name -> Nix attribute-path mapping table.
// Extend this list as you encounter new Python packages.
const MODULE_MAP: &[(&str, &str)] = &[
    ("docopt", "python3Packages.docopt"),
    ("lxml", "python3Packages.lxml"),
    ("selenium", "python3Packages.selenium"),
    ("PIL", "python3Packages.pillow"),
    ("cv2", "python3Packages.opencv4"),
    ("sklearn", "python3Packages.scikit-learn"),
    ("bs4", "python3Packages.beautifulsoup4"),
    ("yaml", "python3Packages.pyyaml"),
    ("requests", "python3Packages.requests"),
    ("numpy", "python3Packages.numpy"),
    ("pandas", "python3Packages.pandas"),
    ("cryptography", "python3Packages.cryptography"),
    ("jwt", "python3Packages.pyjwt"),
    ("dotenv", "python3Packages.python-dotenv"),
];

fn resolve_nix_pkg(import_name: &str) -> String {
    for (key, val) in MODULE_MAP {
        if *key == import_name {
            return val.to_string();
        }
    }
    // Optimistic fallback: assume Nix name mirrors the import name
    format!("python3Packages.{}", import_name)
}

fn run_shell_inject(extra_pkgs: &[String]) {
    // Write the embedded injector script to a temp file, make it executable
    let mut temp = tempfile::NamedTempFile::new().unwrap();
    temp.write_all(INJECTOR_SH.as_bytes()).unwrap();

    let mut perms = std::fs::metadata(temp.path()).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(temp.path(), perms).unwrap();

    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());

    // Base packages always available in an ostadix session
    let mut packages = vec!["sbcl".to_string(), "rlwrap".to_string(), "nix".to_string()];
    packages.extend_from_slice(extra_pkgs);

    println!(
        "\x1b[36m[OSTADIX]\x1b[0m Provisioning Nix environment with: {:?}",
        packages
    );

    Command::new("nix-shell")
        .arg("-p")
        .args(&packages)
        .arg("--run")
        .arg(format!("{} {}", temp.path().display(), shell))
        .status()
        .expect("Failed to launch nix-shell");
}

fn run_auto_resolve(cmd_args: &[String]) {
    // The pyrun-style dependency resolver loop.
    // Keeps executing the command, catching ModuleNotFoundError,
    // resolving the Nix package name, and retrying in an enriched shell.
    let re = Regex::new(r"No module named '([^']+)'").unwrap();
    let mut nix_pkgs: Vec<String> = Vec::new();

    loop {
        let output = if nix_pkgs.is_empty() {
            Command::new(&cmd_args[0])
                .args(&cmd_args[1..])
                .output()
                .expect("Failed to execute command")
        } else {
            Command::new("nix-shell")
                .arg("-p")
                .args(&nix_pkgs)
                .arg("--pure")
                .arg("--run")
                .arg(cmd_args.join(" "))
                .output()
                .expect("Failed to execute nix-shell")
        };

        if output.status.success() {
            print!("{}", String::from_utf8_lossy(&output.stdout));
            break;
        }

        let stderr = String::from_utf8_lossy(&output.stderr);

        if let Some(caps) = re.captures(&stderr) {
            let missing = &caps[1];
            let nix_pkg = resolve_nix_pkg(missing);
            eprintln!(
                "\x1b[36m[OSTADIX]\x1b[0m {} → {}  [auto-resolving]",
                missing, nix_pkg
            );
            nix_pkgs.push(nix_pkg);
        } else {
            // Real error unrelated to missing modules — surface it and exit
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", stderr);
            std::process::exit(output.status.code().unwrap_or(1));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        // ostadix shell [extra-pkgs...]
        // Drops into an ostadix-enriched shell with optional extra Nix packages
        Some("shell") => {
            let extra = args[1..].to_vec();
            run_shell_inject(&extra);
        }

        // ostadix run <command> [args...]
        // Auto-resolves Python ModuleNotFoundErrors via Nix
        Some("run") if args.len() > 1 => {
            run_auto_resolve(&args[1..]);
        }

        // ostadix (no args) — boot a bare ostadix shell
        None => {
            run_shell_inject(&[]);
        }

        _ => {
            eprintln!("Ostadix Shell Engine");
            eprintln!("Usage:");
            eprintln!("  ostadix                         Launch ostadix shell");
            eprintln!("  ostadix shell [pkg1 pkg2 ...]  Launch with extra Nix packages");
            eprintln!("  ostadix run <cmd> [args...]    Auto-resolve Python deps and run");
            std::process::exit(1);
        }
    }
}
