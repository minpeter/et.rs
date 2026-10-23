//! Returning allocator memory that idle sessions no longer use.
//!
//! jemalloc is the Linux global allocator of the shipped binary (see
//! `crates/et-bin/src/main.rs` and `.cargo/config.toml`). Two kinds of freed
//! memory stay resident in a quiet process:
//!
//! - Each thread's cache (`tcache`) keeps recently freed objects for reuse.
//!   jemalloc trims it only while the thread keeps allocating, so a session
//!   thread that goes quiet after a burst holds its cache indefinitely.
//! - Dirty pages decay back to the kernel only when allocator activity drives
//!   the decay clock, which a quiet process does not.
//!
//! Upstream has no counterpart: ET C++ uses glibc malloc and never trims.

use std::time::{Duration, Instant};

/// How long a loop must see no I/O before it returns its caches. Matches the
/// 1 s dirty-page decay of active sessions.
pub const IDLE_RELEASE_DELAY: Duration = Duration::from_secs(1);

/// What an idle loop may release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseScope {
    /// Only the calling thread's cache: other threads of the process keep
    /// allocating (an `etserver` session thread).
    Thread,
    /// The calling thread is the only allocating thread of its process (a
    /// terminal), so it may also purge the arenas' dirty pages.
    Process,
}

/// Releases a poll loop's allocator caches once it has been quiet for
/// [`IDLE_RELEASE_DELAY`], and takes the thread cache back once the loop is
/// busy again.
///
/// The loop bounds each wait by [`IdleRelease::deadline`] and reports every
/// wait to [`IdleRelease::after_wait`]. After a release the deadline is gone,
/// so an idle loop sleeps without a timer until its next event. A lone event
/// after a release (an idle session's keep-alive) is served without the
/// cache, so periodic keep-alives neither rebuild it nor add a wakeup; a
/// second event within [`IDLE_RELEASE_DELAY`] of the previous one rebuilds it.
#[derive(Debug)]
pub struct IdleRelease {
    scope: ReleaseScope,
    last_activity: Instant,
    released: bool,
}

impl IdleRelease {
    pub fn new(scope: ReleaseScope, now: Instant) -> Self {
        Self {
            scope,
            last_activity: now,
            released: false,
        }
    }

    /// When the loop must wake up to release, if it has not released since
    /// it was last busy. Always `None` where there is nothing to release.
    pub fn deadline(&self) -> Option<Instant> {
        (cfg!(target_os = "linux") && !self.released)
            .then(|| self.last_activity + IDLE_RELEASE_DELAY)
    }

    /// Account one wait. `active` is whether the wait reported any I/O.
    pub fn after_wait(&mut self, active: bool, now: Instant) {
        if active {
            if self.released
                && now.saturating_duration_since(self.last_activity) < IDLE_RELEASE_DELAY
            {
                self.released = false;
                #[cfg(target_os = "linux")]
                set_thread_cache(true);
            }
            self.last_activity = now;
        } else if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.released = true;
            #[cfg(target_os = "linux")]
            release(self.scope);
        }
    }

    /// Whether the caches are currently released.
    pub fn released(&self) -> bool {
        self.released
    }
}

#[cfg(target_os = "linux")]
fn release(scope: ReleaseScope) {
    // Disabling the thread cache flushes every cached object back to the
    // arena and frees the cache itself; re-enabling builds an empty one.
    set_thread_cache(false);
    if scope == ReleaseScope::Process {
        // Objects just flushed can leave whole pages free. A quiet process
        // never advances the decay clock, so purge now instead.
        let _ = release_idle_memory();
        restore_active_decay();
    }
}

#[cfg(target_os = "linux")]
fn set_thread_cache(enabled: bool) {
    use tikv_jemalloc_ctl::{Access, AsName};

    let _ = b"thread.tcache.enabled\0".name().write(enabled);
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IdleMemoryAccounting {
    pub(crate) applied_arenas: u32,
    pub(crate) dirty_decay_ms: isize,
    pub(crate) muzzy_decay_ms: isize,
}

/// Return every arena's dirty pages to the kernel now, and keep later frees
/// from lingering until [`restore_active_decay`] runs.
///
/// Two steps are both required. `arenas.*_decay_ms` governs arenas created
/// later, and each arena that already holds session buffers is updated through
/// its own index.
///
/// jemalloc's `MALLCTL_ARENAS_ALL` pseudo-index is deliberately not used: it is
/// rejected with `EFAULT` on some builds, which silently left this policy
/// unapplied at runtime while a future-arena read-back still looked correct.
/// `arenas.narenas` is an upper limit rather than a count of live arenas, so an
/// index that was never initialized also answers `EFAULT`; those arenas hold
/// nothing and inherit the future-arena setting when they are created, so they
/// are skipped instead of failing the release.
#[cfg(target_os = "linux")]
pub(crate) fn release_idle_memory() -> Result<IdleMemoryAccounting, tikv_jemalloc_ctl::Error> {
    use tikv_jemalloc_ctl::{Access, AsName};

    b"arenas.dirty_decay_ms\0".name().write(0_isize)?;
    b"arenas.muzzy_decay_ms\0".name().write(0_isize)?;
    let limit: u32 = b"arenas.narenas\0".name().read()?;
    let mut applied_arenas = 0;
    for index in 0..limit {
        let dirty = format!("arena.{index}.dirty_decay_ms\0");
        if dirty.as_bytes().name().write(0_isize).is_err() {
            continue;
        }
        let muzzy = format!("arena.{index}.muzzy_decay_ms\0");
        let _ = muzzy.as_bytes().name().write(0_isize);
        applied_arenas += 1;
    }
    Ok(IdleMemoryAccounting {
        applied_arenas,
        dirty_decay_ms: b"arenas.dirty_decay_ms\0".name().read()?,
        muzzy_decay_ms: b"arenas.muzzy_decay_ms\0".name().read()?,
    })
}

/// Active-session decay: dirty pages return to the kernel after 1 s (the
/// build-time default, see `.cargo/config.toml`, restated here so builds
/// without that config keep it), and purged pages skip jemalloc's lazy
/// `MADV_FREE` stage (`muzzy_decay_ms` 0, jemalloc's own default): lazily
/// freed pages stay resident until the kernel is under memory pressure.
#[cfg(target_os = "linux")]
pub(crate) fn restore_active_decay() {
    use tikv_jemalloc_ctl::{Access, AsName};

    const DIRTY_DECAY_MS: isize = 1000;
    const MUZZY_DECAY_MS: isize = 0;
    let _ = b"arenas.dirty_decay_ms\0".name().write(DIRTY_DECAY_MS);
    let _ = b"arenas.muzzy_decay_ms\0".name().write(MUZZY_DECAY_MS);
    if let Ok(limit) = b"arenas.narenas\0".name().read() {
        let limit: u32 = limit;
        for index in 0..limit {
            let dirty = format!("arena.{index}.dirty_decay_ms\0");
            if dirty.as_bytes().name().write(DIRTY_DECAY_MS).is_err() {
                continue;
            }
            let muzzy = format!("arena.{index}.muzzy_decay_ms\0");
            let _ = muzzy.as_bytes().name().write(MUZZY_DECAY_MS);
        }
    }
}

// The release policy only exists when jemalloc is the active allocator, which
// the shipped binary installs. Unit tests install it too so they exercise the
// real control path instead of the system allocator.
#[cfg(all(test, target_os = "linux"))]
#[global_allocator]
static TEST_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(test, target_os = "linux"))]
#[path = "idle_memory_tests.rs"]
mod tests;
