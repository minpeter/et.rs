use std::collections::BTreeMap;

use et_cli::tunnel::MAX_UNIX_SOCKET_PATH;
use et_core::packet::{Packet, HEADER_LEN};
use et_core::proto::{InitialPayload, TerminalPacketType};
use et_net::local_packet::MAX_LOCAL_PACKET_LEN;
use prost::Message;

use crate::terminal_protocol::{valid_environment_name, MAX_ENVIRONMENT, MAX_ENV_VALUE};

const MAX_LOSSY_FORWARD_ENV_VALUE: usize = MAX_UNIX_SOCKET_PATH * 3;

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
    environment.sort_unstable_by(|(left, _), (right, _)| {
        locale_priority(left)
            .cmp(&locale_priority(right))
            .then_with(|| left.cmp(right))
    });
    environment.into_iter()
}

fn locale_priority(name: &str) -> u8 {
    match name {
        "LC_ALL" => 0,
        "LC_CTYPE" => 1,
        "LANG" => 2,
        _ => 3,
    }
}

pub(crate) fn reserved_environment_value_lengths<'a>(
    existing: impl IntoIterator<Item = (&'a str, usize)>,
    colorterm: Option<&str>,
    forward_environment: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, usize> {
    let mut reserved: BTreeMap<_, _> = existing
        .into_iter()
        .map(|(name, value_len)| (name.to_owned(), value_len))
        .collect();
    if let Some(value) = colorterm {
        reserved.insert("COLORTERM".to_owned(), value.len());
    }
    for name in forward_environment {
        // A successfully bound Unix socket path is at most 107 raw bytes, but
        // `to_string_lossy()` can expand each non-UTF-8 byte to U+FFFD.
        reserved.insert(name.to_owned(), MAX_LOSSY_FORWARD_ENV_VALUE);
    }
    reserved
}

pub(crate) fn locale_environment_capacity(reserved: usize) -> usize {
    MAX_ENVIRONMENT.saturating_sub(reserved)
}

pub(crate) fn bounded_locale_environment(
    candidates: impl IntoIterator<Item = (String, String)>,
    reserved: &BTreeMap<String, usize>,
) -> Result<Vec<(String, String)>, usize> {
    let mut packet_len = HEADER_LEN;
    for (name, value_len) in reserved {
        packet_len = packet_len
            .saturating_add(encoded_string_field_len(name.len()))
            .saturating_add(encoded_string_field_len(*value_len));
    }
    if packet_len > MAX_LOCAL_PACKET_LEN {
        return Err(packet_len);
    }

    let capacity = locale_environment_capacity(reserved.len());
    let mut selected = Vec::with_capacity(capacity);
    for (name, value) in candidates {
        if reserved.contains_key(&name) || selected.len() == capacity {
            continue;
        }
        let addition = encoded_string_field_len(name.len()) + encoded_string_field_len(value.len());
        if packet_len.saturating_add(addition) <= MAX_LOCAL_PACKET_LEN {
            packet_len += addition;
            selected.push((name, value));
        }
    }
    Ok(selected)
}

pub(crate) fn bound_jumphost_locale_environment(
    payload: &InitialPayload,
    locale: &mut Vec<(String, String)>,
    colorterm: Option<&str>,
) -> Result<(), usize> {
    let mut modeled = payload.clone();
    modeled.jumphost = Some(true);
    modeled.environmentvariables.extend(locale.iter().cloned());
    if let Some(value) = colorterm {
        modeled
            .environmentvariables
            .insert("COLORTERM".to_owned(), value.to_owned());
    }

    loop {
        let packet_len = Packet::new(
            TerminalPacketType::JumphostInit as u8,
            modeled.encode_to_vec(),
        )
        .wire_len();
        if packet_len <= MAX_LOCAL_PACKET_LEN {
            return Ok(());
        }
        let Some((name, _)) = locale.pop() else {
            return Err(packet_len);
        };
        modeled.environmentvariables.remove(&name);
    }
}

fn encoded_string_field_len(value_len: usize) -> usize {
    1usize
        .saturating_add(varint_len(value_len))
        .saturating_add(value_len)
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::{
        bound_jumphost_locale_environment, ghostty_colorterm, locale_environment_capacity,
        locale_priority, normalize_terminal_type, reserved_environment_value_lengths,
        MAX_LOSSY_FORWARD_ENV_VALUE,
    };
    use et_core::packet::Packet;
    use et_core::proto::{
        InitialPayload, PortForwardSourceRequest, SocketEndpoint, TerminalPacketType,
    };
    use et_net::local_packet::MAX_LOCAL_PACKET_LEN;
    use prost::Message;

    #[test]
    fn effective_locale_controls_precede_other_categories() {
        assert!(locale_priority("LC_ALL") < locale_priority("LC_CTYPE"));
        assert!(locale_priority("LC_CTYPE") < locale_priority("LANG"));
        assert!(locale_priority("LANG") < locale_priority("LC_000"));
    }

    #[test]
    fn jumphost_packet_budget_preserves_effective_locale_controls() {
        let request = PortForwardSourceRequest {
            source: None,
            destination: Some(SocketEndpoint {
                name: Some("remote-name-padding".to_owned()),
                port: None,
            }),
            environmentvariable: Some("ET_PIPE".to_owned()),
        };
        let payload = InitialPayload {
            jumphost: Some(false),
            reversetunnels: vec![request; 128],
            environmentvariables: Default::default(),
            flowcontrol: None,
        };
        let mut locale = vec![
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("LC_CTYPE".to_owned(), "C.UTF-8".to_owned()),
            ("LANG".to_owned(), "ko_KR.UTF-8".to_owned()),
        ];
        locale.extend((0..15).map(|index| (format!("LC_000_{index:03}"), "x".repeat(4096))));
        assert!(jumphost_packet_len(&payload, &locale, Some("truecolor")) > MAX_LOCAL_PACKET_LEN);
        bound_jumphost_locale_environment(&payload, &mut locale, Some("truecolor")).unwrap();
        assert!(jumphost_packet_len(&payload, &locale, Some("truecolor")) <= MAX_LOCAL_PACKET_LEN);
        for name in ["LC_ALL", "LC_CTYPE", "LANG"] {
            assert!(locale.iter().any(|(candidate, _)| candidate == name));
        }
    }

    fn jumphost_packet_len(
        payload: &InitialPayload,
        locale: &[(String, String)],
        colorterm: Option<&str>,
    ) -> usize {
        let mut modeled = payload.clone();
        modeled.jumphost = Some(true);
        modeled.environmentvariables.extend(locale.iter().cloned());
        if let Some(value) = colorterm {
            modeled
                .environmentvariables
                .insert("COLORTERM".to_owned(), value.to_owned());
        }
        Packet::new(
            TerminalPacketType::JumphostInit as u8,
            modeled.encode_to_vec(),
        )
        .wire_len()
    }

    #[test]
    fn locale_capacity_reserves_terminal_environment_entries() {
        assert_eq!(locale_environment_capacity(0), 128);
        assert_eq!(locale_environment_capacity(2), 126);
        assert_eq!(locale_environment_capacity(128), 0);
        assert_eq!(locale_environment_capacity(usize::MAX), 0);
    }

    #[test]
    fn locale_capacity_counts_distinct_reserved_names() {
        let reserved = reserved_environment_value_lengths(
            [("COLORTERM", 4), ("LC_COLLISION", 1)],
            Some("truecolor"),
            ["ET_PIPE", "ET_PIPE", "LC_COLLISION"],
        );
        assert_eq!(
            reserved.into_keys().collect::<Vec<_>>(),
            ["COLORTERM", "ET_PIPE", "LC_COLLISION"],
        );
        let reserved = reserved_environment_value_lengths(
            [("COLORTERM", 4), ("LC_COLLISION", 1)],
            Some("truecolor"),
            ["ET_PIPE", "ET_PIPE", "LC_COLLISION"],
        );
        assert_eq!(reserved["COLORTERM"], "truecolor".len());
        assert_eq!(reserved["ET_PIPE"], MAX_LOSSY_FORWARD_ENV_VALUE);
        assert_eq!(reserved["LC_COLLISION"], MAX_LOSSY_FORWARD_ENV_VALUE);
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
