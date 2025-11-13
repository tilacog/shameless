//! Threshold newtype for Shamir Secret Sharing

use anyhow::Result;

/// Threshold for Shamir Secret Sharing (2..=255)
///
/// Invariant: threshold >= 2 (enforced at construction)
/// A threshold of 1 provides no security benefit since any single share can recover the entire secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Threshold(u8);

impl Threshold {
    /// Creates a new threshold, returning an error if value < 2
    ///
    /// # Errors
    /// Returns an error if the threshold is less than 2
    ///
    /// # Examples
    ///
    /// ```rust
    /// use shameless::domain::Threshold;
    ///
    /// // Valid threshold (2 or greater)
    /// let threshold = Threshold::new(3).unwrap();
    /// assert_eq!(*threshold, 3);
    ///
    /// // Invalid: threshold must be at least 2
    /// assert!(Threshold::new(1).is_err());
    /// assert!(Threshold::new(0).is_err());
    /// ```
    pub fn new(value: u8) -> Result<Self> {
        if value < 2 {
            anyhow::bail!("Threshold must be at least 2 (got {value})");
        }
        Ok(Self(value))
    }
}

impl std::ops::Deref for Threshold {
    type Target = u8;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
