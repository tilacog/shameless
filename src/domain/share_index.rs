//! `ShareIndex` newtype for Shamir Secret Sharing

use anyhow::{Result, bail};

/// Share index (0..=254)
///
/// Represents the index of a share in Shamir Secret Sharing.
/// Index 255 is reserved by the blahaj crate for GF256 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareIndex(u8);

impl ShareIndex {
    /// Maximum valid share index (254)
    pub const MAX: u8 = 254;

    /// Creates a new share index
    ///
    /// # Errors
    /// Returns an error if index is 255 (reserved for GF256 operations)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use shameless::domain::ShareIndex;
    ///
    /// // Valid indices (0-254)
    /// let index = ShareIndex::new(0).unwrap();
    /// assert_eq!(*index, 0);
    ///
    /// let max_index = ShareIndex::new(ShareIndex::MAX).unwrap();
    /// assert_eq!(*max_index, 254);
    ///
    /// // Invalid: 255 is reserved
    /// assert!(ShareIndex::new(255).is_err());
    /// ```
    pub fn new(value: u8) -> Result<Self> {
        if value == 255 {
            bail!("Share index 255 is reserved for GF256 operations");
        }
        Ok(Self(value))
    }
}

impl std::ops::Deref for ShareIndex {
    type Target = u8;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
