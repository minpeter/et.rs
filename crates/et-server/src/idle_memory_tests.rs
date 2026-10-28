use std::time::{Duration, Instant};

use super::{IdleRelease, ReleaseScope, IDLE_RELEASE_DELAY};

fn thread_cache_enabled() -> bool {
    use tikv_jemalloc_ctl::{Access, AsName};

    b"thread.tcache.enabled\0".name().read().unwrap()
}

/// A real server run applied this policy to zero arenas while still
/// reading back a configured future-arena value, so the release looked
/// successful and reclaimed nothing. Assert the live-arena count it
/// actually reached.
#[test]
fn idle_release_reaches_at_least_one_live_arena() {
    let accounting = super::release_idle_memory().expect("release must succeed under jemalloc");
    assert_eq!(accounting.dirty_decay_ms, 0);
    assert_eq!(accounting.muzzy_decay_ms, 0);
    assert!(
        accounting.applied_arenas >= 1,
        "release applied to no live arena: {accounting:?}"
    );
    super::restore_active_decay();
}

#[test]
fn quiet_loop_returns_its_thread_cache_and_keepalives_do_not_rebuild_it() {
    std::thread::spawn(|| {
        let start = Instant::now();
        let mut idle = IdleRelease::new(ReleaseScope::Thread, start);
        assert!(thread_cache_enabled());

        // Activity pushes the release back; a timeout before it keeps the cache.
        idle.after_wait(true, start + Duration::from_millis(900));
        idle.after_wait(false, start + Duration::from_millis(1500));
        assert!(!idle.released() && thread_cache_enabled());
        assert_eq!(
            idle.deadline(),
            Some(start + Duration::from_millis(900) + IDLE_RELEASE_DELAY)
        );

        // A quiet second releases it, and the loop no longer needs a timer.
        let released_at = start + Duration::from_millis(1900);
        idle.after_wait(false, released_at);
        assert!(idle.released() && !thread_cache_enabled());
        assert_eq!(idle.deadline(), None);

        // Keep-alives seconds apart are served without rebuilding the cache.
        let keepalive = released_at + Duration::from_secs(5);
        idle.after_wait(true, keepalive);
        idle.after_wait(true, keepalive + Duration::from_secs(5));
        assert!(idle.released() && !thread_cache_enabled());

        // Back-to-back events mean the session is busy again.
        idle.after_wait(true, keepalive + Duration::from_millis(5100));
        assert!(!idle.released() && thread_cache_enabled());
        assert_eq!(
            idle.deadline(),
            Some(keepalive + Duration::from_millis(5100) + IDLE_RELEASE_DELAY)
        );
    })
    .join()
    .unwrap();
}

#[test]
fn process_release_purges_dirty_pages_and_restores_active_decay() {
    use tikv_jemalloc_ctl::{epoch, Access, AsName};

    std::thread::spawn(|| {
        let start = Instant::now();
        let mut idle = IdleRelease::new(ReleaseScope::Process, start);
        // Free enough whole pages that they sit dirty until a purge.
        drop(std::hint::black_box(vec![1_u8; 4 << 20]));
        idle.after_wait(false, start + IDLE_RELEASE_DELAY);
        assert!(idle.released() && !thread_cache_enabled());
        epoch::advance().unwrap();
        let dirty_pages: usize = b"stats.arenas.0.pdirty\0".name().read().unwrap();
        // Other test threads may free a few pages meanwhile, never 4 MiB.
        assert!(dirty_pages < 256, "{dirty_pages} dirty pages left");
        let dirty_decay_ms: isize = b"arenas.dirty_decay_ms\0".name().read().unwrap();
        assert_eq!(dirty_decay_ms, 1000);
    })
    .join()
    .unwrap();
}
