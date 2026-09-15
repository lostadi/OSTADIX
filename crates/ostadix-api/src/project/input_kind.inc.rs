// Shared, dependency-free routing hint for the native intent front door,
// project compiler, and independently built MCP. Extraction validates payloads.

/// Outer sentinel marking the start of the embedded project bundle.
pub const BUNDLE_BEGIN: &str = "# O-PROJECT-BUNDLE-V1 BEGIN";
/// Inner sentinel marking the start of the base64 payload lines.
const PAYLOAD_BEGIN: &str = "#olang-bundle-payload-begin";

/// Detect a lifted project before ordinary O evaluation, which is inert for
/// these containers. Matching markers do not establish a valid bundle.
pub fn has_embedded_bundle(source: &str) -> bool {
    source.contains(BUNDLE_BEGIN) && source.contains(PAYLOAD_BEGIN)
}
