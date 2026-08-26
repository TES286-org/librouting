//! Time and clock abstractions.
//!
//! The embedder injects time into the library. `Instant` is a logical
//! millisecond counter (monotonic). `Duration` is a span of milliseconds.
//! This decouples the library from wall-clock and async runtimes.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(pub u64);

impl Instant {
    pub const ZERO: Self = Self(0);

    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1000)
    }

    pub fn as_millis(self) -> u64 {
        self.0
    }

    pub fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    pub fn checked_sub(self, other: Self) -> Option<Duration> {
        self.0.checked_sub(other.0).map(Duration)
    }

    pub fn saturating_sub(self, other: Self) -> Duration {
        Duration(self.0.saturating_sub(other.0))
    }

    pub fn checked_add(self, dur: Duration) -> Option<Self> {
        self.0.checked_add(dur.0).map(Self)
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={}ms", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(pub u64);

impl Duration {
    pub const ZERO: Self = Self(0);

    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1000)
    }

    pub fn as_millis(self) -> u64 {
        self.0
    }

    pub fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Injectable clock. The library never reads wall-clock itself.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// A deterministic clock for tests.
#[cfg(feature = "std")]
pub struct FakeClock {
    inner: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "std")]
impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl FakeClock {
    pub fn new() -> Self {
        Self { inner: 0.into() }
    }

    pub fn advance(&self, dur: Duration) {
        self.inner
            .fetch_add(dur.0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set(&self, t: Instant) {
        self.inner.store(t.0, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "std")]
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        Instant(self.inner.load(std::sync::atomic::Ordering::Relaxed))
    }
}
