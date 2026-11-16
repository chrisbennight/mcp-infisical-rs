//! Request ownership and continuing permission for the existing transfer plane.

use crate::approval::ApprovalOwner;
use std::{future::Future, sync::Arc};

#[derive(Clone, Default)]
pub(super) struct FileAccess {
    owner: Option<ApprovalOwner>,
    guard: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

tokio::task_local! { static ACCESS: FileAccess; }

impl FileAccess {
    pub(super) fn current() -> Self {
        ACCESS.try_with(Clone::clone).unwrap_or_default()
    }
    pub(super) fn owns_current(&self) -> bool {
        self.owner == Self::current().owner
    }
    pub(super) fn active(&self) -> bool {
        self.guard.as_ref().is_none_or(|guard| guard())
    }
}

pub(crate) async fn with_access<T>(
    owner: Option<ApprovalOwner>,
    guard: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    future: impl Future<Output = T>,
) -> T {
    ACCESS.scope(FileAccess { owner, guard }, future).await
}
