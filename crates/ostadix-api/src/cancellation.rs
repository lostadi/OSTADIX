//! A cooperative cancellation token.
//!
//! Shared by embedding requests, backend processes, and group `any`/`race` handling: once one member has produced the
//! selected result, the coordinator can signal siblings that their result is
//! no longer needed. Cancellation is cooperative — workers observe the flag at
//! safe points and stop early where practical. The token itself does not stop a
//! process; its owner applies the existing bounded process-lifecycle cleanup.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Causal identity attached only when an execution owner actually observes
/// request cancellation and returns it as the execution failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct RequestCancellationObserved(pub(crate) String);

pub(crate) fn is_request_cancellation(error: &anyhow::Error) -> bool {
    error.is::<RequestCancellationObserved>()
        || error
            .chain()
            .any(|cause| cause.is::<RequestCancellationObserved>())
}

/// A shareable, cheaply-clonable cancellation flag.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
    parents: Arc<[CancellationToken]>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            parents: Arc::from([]),
        }
    }

    /// Create an independently cancellable child which observes this token.
    /// Cancelling a child never cancels its parent or a sibling.
    pub fn child_token(&self) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            parents: Arc::from([self.clone()]),
        }
    }

    /// Observe both an enclosing request and an independently owned branch.
    pub(crate) fn linked_child(&self, other: &Self) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            parents: Arc::from([self.clone(), other.clone()]),
        }
    }

    /// Request cancellation. Idempotent. Parent and sibling tokens are unchanged.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst) || self.parents.iter().any(Self::is_cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_cancellation_is_independent_but_request_reaches_every_descendant() {
        let request = CancellationToken::new();
        let winner = request.child_token();
        let loser = request.child_token();
        let nested = winner.child_token();
        loser.cancel();
        assert!(loser.is_cancelled());
        assert!(!request.is_cancelled());
        assert!(!winner.is_cancelled());
        assert!(!nested.is_cancelled());
        request.cancel();
        assert!(winner.is_cancelled());
        assert!(nested.is_cancelled());
        assert!(request.child_token().is_cancelled());
    }

    #[test]
    fn linked_child_observes_both_owners_without_cancelling_them() {
        for cancel_request in [false, true] {
            let request = CancellationToken::new();
            let branch = CancellationToken::new();
            let combined = request.linked_child(&branch);
            if cancel_request {
                request.cancel();
            } else {
                branch.cancel();
            }
            assert!(combined.is_cancelled());
            assert_eq!(request.is_cancelled(), cancel_request);
            assert_eq!(branch.is_cancelled(), !cancel_request);
        }
    }

    #[test]
    fn token_starts_uncancelled_and_latches() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        let clone = token.clone();
        assert!(clone.is_cancelled());
    }
}
