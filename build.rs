#[path = "scripts/capture_build_identity.rs"]
mod capture_build_identity;

fn main() {
    capture_build_identity::capture(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
}
