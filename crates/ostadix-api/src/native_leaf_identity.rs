//! Stable native-leaf spelling and byte identity, independent of execution.

use sha2::{Digest, Sha256};

pub const BUILTIN: &str = "ocore_i64";

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn native_leaf_identity_preserves_sha256_bytes() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_ne!(digest(b"abc"), digest(b"abc\n"));
    }
}
