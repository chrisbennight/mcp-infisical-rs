use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

/// Maximum number of records returned by one typed collection call.
pub const MAX_PAGE_SIZE: u16 = 100;
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
    #[schemars(range(min = 1, max = 100))]
    limit: u16,
}

impl PageRequest {
    /// Construct a bounded page request.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is zero or above [`MAX_PAGE_SIZE`], or
    /// when the offset is above [`MAX_PAGE_OFFSET`].
    pub fn new(offset: u32, limit: u16) -> Result<Self, PaginationError> {
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(PaginationError::InvalidLimit);
        }
        if offset > MAX_PAGE_OFFSET {
            return Err(PaginationError::OffsetLimit);
        }
        Ok(Self { offset, limit })
    }

    /// Zero-based collection offset.
    #[must_use]
    pub fn offset(self) -> u32 {
        self.offset
    }

    /// Maximum records requested from the endpoint.
    #[must_use]
    pub fn limit(self) -> u16 {
        self.limit
    }

    fn next(self, returned: usize, total: Option<u64>) -> Result<Option<Self>, PaginationError> {
        if returned > usize::from(self.limit) {
            return Err(PaginationError::OversizedPage);
        }
        let returned = u32::try_from(returned).map_err(|_| PaginationError::OversizedPage)?;
        let next_offset = self
            .offset
            .checked_add(returned)
            .ok_or(PaginationError::OffsetLimit)?;
        let reached_reported_total = total.is_some_and(|total| u64::from(next_offset) >= total);
        if returned == 0 || returned < u32::from(self.limit) || reached_reported_total {
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
        Ok(Self { items, next, total })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PaginationError {
    #[error("page limit must be between 1 and 100")]
    InvalidLimit,
    #[error("page offset exceeds the bounded traversal limit")]
    OffsetLimit,
    #[error("Infisical returned more records than the requested page limit")]
    OversizedPage,
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::{MAX_PAGE_OFFSET, MAX_PAGE_SIZE, Page, PageRequest, PaginationError};

    #[test]
    fn pagination_is_bounded_and_continuations_follow_the_contract() {
        assert_eq!(
            PageRequest::new(0, 0).unwrap_err(),
            PaginationError::InvalidLimit
        );
        assert_eq!(
            PageRequest::new(0, MAX_PAGE_SIZE + 1).unwrap_err(),
            PaginationError::InvalidLimit
        );
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
        assert_eq!(schema["properties"]["limit"]["maximum"], MAX_PAGE_SIZE);
    }
}
