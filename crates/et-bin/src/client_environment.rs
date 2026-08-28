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
    std::env::vars_os().filter_map(|(name, value)| {
        let name = name.into_string().ok()?;
        if name != "LANG" && !name.starts_with("LC_") {
            return None;
        }
        Some((name, value.into_string().ok()?))
    })
}

#[cfg(test)]
mod tests {
    use super::{ghostty_colorterm, normalize_terminal_type};

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
