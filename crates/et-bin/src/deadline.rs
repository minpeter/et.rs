use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    expires_at: Instant,
}

impl Deadline {
    pub fn after(timeout: Duration) -> Self {
        let now = Instant::now();
        let expires_at = match now.checked_add(timeout) {
            Some(expires_at) => expires_at,
            None => now,
        };
        Self { expires_at }
    }

    pub fn remaining(self) -> Option<Duration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
    }

    pub fn expires_at(self) -> Instant {
        self.expires_at
    }
}
