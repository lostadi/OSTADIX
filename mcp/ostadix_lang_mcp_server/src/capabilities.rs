//! The human CLI and MCP compile the same catalog and read-only resolver.
#[path = "../../../src/command_catalog.rs"]
mod shared;

pub(crate) use shared::{binary_path, catalog, guide, resolve_command, GUIDE_TOPICS};
