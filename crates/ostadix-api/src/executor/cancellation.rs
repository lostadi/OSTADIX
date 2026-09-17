//! Compatibility path for the shared cooperative cancellation token.

pub use crate::cancellation::CancellationToken;

#[cfg(test)]
mod tests {
    #[test]
    fn compatibility_paths_share_cancellation_across_threads() {
        let canonical = crate::cancellation::CancellationToken::new();
        let nested: super::CancellationToken = canonical.clone();
        let executor: crate::executor::CancellationToken = nested.clone();

        std::thread::spawn(move || nested.cancel()).join().unwrap();

        assert!(canonical.is_cancelled());
        assert!(executor.is_cancelled());
    }
}
