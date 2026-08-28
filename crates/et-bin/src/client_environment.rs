use crate::terminal_protocol::{valid_environment_name, MAX_ENVIRONMENT, MAX_ENV_VALUE};

pub(crate) fn normalize_terminal_type(term: Option<&str>) -> String {
    match term {
        None | Some("xterm-ghostty") => "xterm-256color".to_owned(),
        Some(term) => term.to_owned(),
    }
}

pub(crate) fn ghostty_colorterm<'a>(
    term: Option<&str>,
    colorterm: Option<&'a str>,
) -> Option<&'a str> {
    match (term, colorterm) {
        (Some("xterm-ghostty"), Some(value @ ("truecolor" | "24bit"))) => Some(value),
        _ => None,
    }
}

/// Collect locale variables matched by OpenSSH's `SendEnv LANG LC_*`.
pub(crate) fn ssh_locale_environment() -> impl Iterator<Item = (String, String)> {
    let mut environment: Vec<_> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            if (name != "LANG" && !name.starts_with("LC_")) || !valid_environment_name(&name) {
                return None;
            }
            let value = value.into_string().ok()?;
            (value.len() <= MAX_ENV_VALUE).then_some((name, value))
        })
        .collect();
    environment.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    environment.into_iter()
}

pub(crate) fn locale_environment_capacity(
    existing: usize,
    has_colorterm: bool,
    forward_environment: usize,
) -> usize {
    let reserved = existing
        .saturating_add(usize::from(has_colorterm))
        .saturating_add(forward_environment);
    MAX_ENVIRONMENT.saturating_sub(reserved)
}

#[cfg(test)]
mod tests {
    use super::{ghostty_colorterm, locale_environment_capacity, normalize_terminal_type};

    #[test]
    fn locale_capacity_reserves_terminal_environment_entries() {
        assert_eq!(locale_environment_capacity(0, false, 0), 128);
        assert_eq!(locale_environment_capacity(0, true, 1), 126);
        assert_eq!(locale_environment_capacity(127, false, 1), 0);
        assert_eq!(locale_environment_capacity(usize::MAX, true, usize::MAX), 0);
    }

    #[test]
    fn ghostty_term_uses_compatible_remote_fallback() {
        assert_eq!(normalize_terminal_type(None), "xterm-256color");
        assert_eq!(
            normalize_terminal_type(Some("xterm-ghostty")),
            "xterm-256color"
        );
        for term in [
            "xterm-256color",
            "screen-256color",
            "linux",
            "xterm-kitty",
            "arbitrary-term",
        ] {
            assert_eq!(normalize_terminal_type(Some(term)), term);
        }
    }

    #[test]
    fn ghostty_truecolor_hint_is_forwarded_only_for_known_values() {
        assert_eq!(
            ghostty_colorterm(Some("xterm-ghostty"), Some("truecolor")),
            Some("truecolor")
        );
        assert_eq!(
            ghostty_colorterm(Some("xterm-ghostty"), Some("24bit")),
            Some("24bit")
        );
        assert_eq!(
            ghostty_colorterm(Some("xterm-ghostty"), Some("unexpected")),
            None
        );
        assert_eq!(
            ghostty_colorterm(Some("xterm-256color"), Some("truecolor")),
            None
        );
        assert_eq!(ghostty_colorterm(Some("xterm-ghostty"), None), None);
    }
}
