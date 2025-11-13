//! Configuration validation for Shamir Secret Sharing splits

use anyhow::{Result, bail};

use super::{ShareCount, Threshold};

/// Validated pair of threshold and share count
///
/// Enforces the invariant that threshold <= `share_count` at the type level.
/// This prevents creating configurations where more shares are required
/// than actually exist.
#[derive(Debug, Clone, Copy)]
pub struct SplitConfig {
    threshold: Threshold,
    share_count: ShareCount,
}

impl SplitConfig {
    /// Creates a new split configuration
    ///
    /// # Errors
    /// Returns an error if threshold exceeds share count
    ///
    /// # Examples
    ///
    /// ```rust
    /// use shameless::domain::{SplitConfig, Threshold, ShareCount};
    ///
    /// // Valid: threshold <= share_count
    /// let config = SplitConfig::new(
    ///     Threshold::new(3).unwrap(),
    ///     ShareCount::new(5).unwrap()
    /// ).unwrap();
    ///
    /// assert_eq!(*config.threshold(), 3);
    /// assert_eq!(*config.share_count(), 5);
    ///
    /// // Invalid: threshold > share_count
    /// let result = SplitConfig::new(
    ///     Threshold::new(5).unwrap(),
    ///     ShareCount::new(3).unwrap()
    /// );
    /// assert!(result.is_err());
    /// ```
    pub fn new(threshold: Threshold, share_count: ShareCount) -> Result<Self> {
        if *threshold > *share_count {
            bail!(
                "Threshold {} cannot exceed share count {}",
                *threshold,
                *share_count
            );
        }
        Ok(Self {
            threshold,
            share_count,
        })
    }

    /// Gets the threshold value
    #[must_use]
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    /// Gets the share count value
    #[must_use]
    pub fn share_count(&self) -> ShareCount {
        self.share_count
    }
}
