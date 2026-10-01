use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

/// Maximum page size supported by the certificate inventory endpoint.
pub const MAX_PAGE_SIZE: usize = 100;
/// Maximum supported offset for one bounded MCP collection traversal.
pub const MAX_PAGE_OFFSET: u32 = 100_000;

/// A validated offset window for one bounded collection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageRequest {
    /// Zero-based offset into the bounded collection.
    #[schemars(range(min = 0, max = 100_000))]
    offset: u32,
    /// Maximum number of records returned by this page.
    #[schemars(range(min = 1))]
    limit: usize,
    #[serde(skip)]
    #[schemars(skip)]
    effective_limit: Option<usize>,
}

impl PageRequest {
    /// Construct a bounded page request.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is zero, or
    /// when the offset is above [`MAX_PAGE_OFFSET`].
    pub fn new(offset: u32, limit: usize) -> Result<Self, PaginationError> {
        if limit == 0 {
            return Err(PaginationError::InvalidLimit);
        }
        if offset > MAX_PAGE_OFFSET {
            return Err(PaginationError::OffsetLimit);
        }
        Ok(Self {
            offset,
            limit,
            effective_limit: None,
        })
    }

    /// Zero-based collection offset.
    #[must_use]
    pub fn offset(self) -> u32 {
        self.offset
    }

    /// Maximum records requested from the endpoint.
    #[must_use]
    pub fn limit(self) -> usize {
        self.effective_limit.unwrap_or(self.limit)
    }

    /// Apply the selected upstream endpoint's documented page-size ceiling.
    #[must_use]
    pub(crate) fn clamped_to(mut self, maximum: usize) -> Self {
        assert!(maximum > 0);
        self.effective_limit = Some(self.limit().min(maximum));
        self
    }

    fn next(self, returned: usize, total: Option<u64>) -> Result<Option<Self>, PaginationError> {
        if returned > self.limit() {
            return Err(PaginationError::OversizedPage);
        }
        let short_page = returned < self.limit();
        let returned = u32::try_from(returned).map_err(|_| PaginationError::OversizedPage)?;
        let next_offset = self
            .offset
            .checked_add(returned)
            .ok_or(PaginationError::OffsetLimit)?;
        let reached_reported_total = total.is_some_and(|total| u64::from(next_offset) >= total);
        if returned == 0 || short_page || reached_reported_total {
            return Ok(None);
        }
        Ok(Some(Self::new(next_offset, self.limit)?))
    }
}

/// One bounded collection response and its validated continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Page<T> {
    /// Records in this bounded page.
    pub items: Vec<T>,
    /// Validated continuation coordinates, or null at the end of the collection.
    pub next: Option<PageRequest>,
    /// Total records reported or computed for the collection, when known.
    pub total: Option<u64>,
    /// Positive count supplied by the caller before upstream clamping.
    #[serde(rename = "requestedLimit")]
    pub requested_limit: usize,
    /// Count sent to the endpoint or applied to the local collection.
    #[serde(rename = "effectiveLimit")]
    pub effective_limit: usize,
    /// Number of records returned in this response.
    pub returned: usize,
}

impl<T> Page<T> {
    /// Build a page from a typed upstream collection response.
    ///
    /// # Errors
    ///
    /// Returns an error when the upstream page exceeds the requested limit or
    /// advancing the offset would exceed the traversal bound.
    pub fn new(
        request: PageRequest,
        items: Vec<T>,
        total: Option<u64>,
    ) -> Result<Self, PaginationError> {
        let next = request.next(items.len(), total)?;
        Ok(Self {
            returned: items.len(),
            items,
            next,
            total,
            requested_limit: request.limit,
            effective_limit: request.limit(),
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PaginationError {
    #[error("page limit must be positive")]
    InvalidLimit,
    #[error("page offset exceeds the bounded traversal limit")]
    OffsetLimit,
    #[error("Infisical returned more records than the requested page limit")]
    OversizedPage,
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::{MAX_PAGE_OFFSET, Page, PageRequest, PaginationError};

    #[test]
    fn pagination_is_bounded_and_continuations_follow_the_contract() {
        assert_eq!(
            PageRequest::new(0, 0).unwrap_err(),
            PaginationError::InvalidLimit
        );
        assert_eq!(PageRequest::new(0, usize::MAX).unwrap().limit(), usize::MAX);
        assert_eq!(
            PageRequest::new(MAX_PAGE_OFFSET + 1, 1).unwrap_err(),
            PaginationError::OffsetLimit
        );

        let request = PageRequest::new(20, 2).unwrap();
        assert_eq!(request.offset(), 20);
        assert_eq!(request.limit(), 2);

        let page = Page::new(request, vec!["a", "b"], Some(25)).unwrap();
        assert_eq!(page.next, Some(PageRequest::new(22, 2).unwrap()));

        let short_page_without_total = Page::new(page.next.unwrap(), vec!["c"], None).unwrap();
        assert!(short_page_without_total.next.is_none());

        let reported_total_page = Page::new(request, vec!["a", "b"], Some(22)).unwrap();
        assert!(reported_total_page.next.is_none());

        let empty_page = Page::<&str>::new(request, Vec::new(), None).unwrap();
        assert!(empty_page.next.is_none());
        assert_eq!(
            Page::new(request, vec!["a", "b", "c"], None).unwrap_err(),
            PaginationError::OversizedPage
        );

        let schema = serde_json::to_value(schema_for!(PageRequest)).unwrap();
        assert_eq!(schema["properties"]["offset"]["maximum"], MAX_PAGE_OFFSET);
        assert_eq!(schema["properties"]["limit"]["minimum"], 1);
        assert!(schema["properties"]["limit"].get("maximum").is_none());
    }

    #[test]
    fn endpoint_clamping_reports_counts_and_preserves_requested_continuation() {
        let requested = PageRequest::new(0, usize::MAX).unwrap();
        let page = Page::new(requested.clamped_to(100), vec![0; 100], Some(250)).unwrap();
        assert_eq!(page.requested_limit, usize::MAX);
        assert_eq!(page.effective_limit, 100);
        assert_eq!(page.returned, 100);
        assert_eq!(page.next, Some(PageRequest::new(100, usize::MAX).unwrap()));
        let next = page.next.unwrap().clamped_to(100);
        assert_eq!(next.limit(), 100);
        let short = Page::new(next, vec![0; 50], Some(150)).unwrap();
        assert!(short.next.is_none());
        let local = Page::new(requested, vec![0; 300], Some(300)).unwrap();
        assert_eq!(local.effective_limit, usize::MAX);
        assert_eq!(local.returned, 300);
        assert!(local.next.is_none());
    }
}
