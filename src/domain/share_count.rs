//! `ShareCount` newtype for Shamir Secret Sharing

use anyhow::{Result, bail};

/// Number of shares to create (1..=254)
///
/// Represents the total number of shares that will be created.
/// The maximum is 254 due to GF256 limitations in the blahaj crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareCount(u8);

impl ShareCount {
    /// Minimum valid share count
    pub const MIN: u8 = 1;

    /// Maximum valid share count (254)
    pub const MAX: u8 = 254;

    /// Creates a new share count
    ///
    /// # Errors
    /// Returns an error if count is 0 or 255
    ///
    /// # Examples
    ///
    /// ```rust
    /// use shameless::domain::ShareCount;
    ///
    /// // Valid share counts (1-254)
    /// let count = ShareCount::new(5).unwrap();
    /// assert_eq!(*count, 5);
    ///
    /// let max_count = ShareCount::new(ShareCount::MAX).unwrap();
    /// assert_eq!(*max_count, 254);
    ///
    /// // Invalid: 0 and 255 are not allowed
    /// assert!(ShareCount::new(0).is_err());
    /// assert!(ShareCount::new(255).is_err());
    /// ```
    pub fn new(value: u8) -> Result<Self> {
        if value == 0 {
            bail!("Share count must be at least 1");
        }
        if value == 255 {
            bail!("Share count maximum is 254 due to GF256 limitations");
        }
        Ok(Self(value))
    }
}

impl std::ops::Deref for ShareCount {
    type Target = u8;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
