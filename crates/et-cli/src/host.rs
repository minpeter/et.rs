//! Host-string parsers mirroring upstream exactly.
//!
//! [`parse_host_string`] is the *jumphost* grammar from `HostParsing.hpp`:
//! `[user@]host[:port]` with bracket IPv6 notation (`[::1]:22`). It never
//! fails — malformed input is returned literally.
//!
//! [`parse_positional_host`] is the `et` client positional grammar from
//! `TerminalClientMain.cpp`: bare IPv6 is disambiguated from a trailing port
//! by counting colons, so an unbracketed full IPv6 must have exactly 7 colons
//! (no port) or 8 (with port).

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedHostString {
    pub user: String,
    pub host: String,
    pub port_suffix: String,
}

pub fn parse_host_string(input: &str) -> ParsedHostString {
    let mut result = ParsedHostString::default();
    let mut remaining = input;

    if let Some(at) = remaining.find('@') {
        result.user = remaining[..at].to_string();
        remaining = &remaining[at + 1..];
    }

    if remaining.starts_with('[') {
        if let Some(close) = remaining.find(']') {
            result.host = remaining[..=close].to_string();
            let after = &remaining[close + 1..];
            if let Some(rest) = after.strip_prefix(':') {
                result.port_suffix = format!(":{rest}");
            }
        } else {
            result.host = remaining.to_string();
        }
    } else if let Some(colon) = remaining.find(':') {
        result.port_suffix = remaining[colon..].to_string();
        result.host = remaining[..colon].to_string();
    } else {
        result.host = remaining.to_string();
    }

    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    InvalidColonCount(String),
    BadPort(String),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidColonCount(s) => write!(f, "invalid host (bad colon count): {s}"),
            Self::BadPort(s) => write!(f, "invalid port: {s}"),
        }
    }
}

impl std::error::Error for HostError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

pub fn parse_positional_host(input: &str, default_port: u16) -> Result<Destination, HostError> {
    let (user, mut host_arg) = match input.find('@') {
        Some(at) => (Some(input[..at].to_string()), input[at + 1..].to_string()),
        None => (None, input.to_string()),
    };

    let colon_count = host_arg.matches(':').count();
    let port;

    let no_port_ipv6 = colon_count == 0 || host_arg.contains("::") || colon_count == 7;
    if no_port_ipv6 {
        port = default_port;
    } else if colon_count == 1 || colon_count == 8 {
        let pos = host_arg.rfind(':').unwrap();
        port = host_arg[pos + 1..]
            .parse::<u16>()
            .map_err(|_| HostError::BadPort(host_arg[pos + 1..].to_string()))?;
        host_arg.truncate(pos);
    } else {
        return Err(HostError::InvalidColonCount(input.to_string()));
    }

    Ok(Destination {
        user,
        host: host_arg,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumphost_golden_fixtures() {
        let cases: &[(&str, &str, &str, &str)] = &[
            ("example.com", "", "example.com", ""),
            ("example.com:22", "", "example.com", ":22"),
            ("user@example.com", "user", "example.com", ""),
            ("user@example.com:2222", "user", "example.com", ":2222"),
            ("192.168.1.1", "", "192.168.1.1", ""),
            ("192.168.1.1:22", "", "192.168.1.1", ":22"),
            ("[::1]", "", "[::1]", ""),
            ("[::1]:22", "", "[::1]", ":22"),
            ("user@[::1]", "user", "[::1]", ""),
            ("user@[::1]:2222", "user", "[::1]", ":2222"),
            ("[2001:db8::1]:22", "", "[2001:db8::1]", ":22"),
            ("admin@[fe80::1%eth0]:22", "admin", "[fe80::1%eth0]", ":22"),
            ("", "", "", ""),
            ("[::1", "", "[::1", ""),
            ("user@[::1", "user", "[::1", ""),
        ];
        for (input, user, host, port) in cases {
            let r = parse_host_string(input);
            assert_eq!(r.user, *user, "user mismatch for {input:?}");
            assert_eq!(r.host, *host, "host mismatch for {input:?}");
            assert_eq!(r.port_suffix, *port, "port mismatch for {input:?}");
        }
    }

    #[test]
    fn positional_simple_host() {
        let d = parse_positional_host("example.com", 2022).unwrap();
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, 2022);
        assert_eq!(d.user, None);
    }

    #[test]
    fn positional_user_host_port() {
        let d = parse_positional_host("user@example.com:2222", 2022).unwrap();
        assert_eq!(d.user.as_deref(), Some("user"));
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, 2222);
    }

    #[test]
    fn positional_ipv4_with_port() {
        let d = parse_positional_host("192.168.1.1:8080", 2022).unwrap();
        assert_eq!(d.host, "192.168.1.1");
        assert_eq!(d.port, 8080);
    }

    #[test]
    fn positional_abbreviated_ipv6_no_port() {
        let d = parse_positional_host("::1", 2022).unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, 2022);
    }

    #[test]
    fn positional_abbreviated_ipv6_full() {
        let d = parse_positional_host("2001:db8::1", 2022).unwrap();
        assert_eq!(d.host, "2001:db8::1");
        assert_eq!(d.port, 2022);
    }

    #[test]
    fn positional_full_ipv6_no_port() {
        let addr = "2001:0db8:0000:0000:0000:0000:0000:0001";
        let d = parse_positional_host(addr, 2022).unwrap();
        assert_eq!(d.host, addr);
        assert_eq!(d.port, 2022);
    }

    #[test]
    fn positional_full_ipv6_with_port() {
        let addr = "2001:0db8:0000:0000:0000:0000:0000:0001";
        let d = parse_positional_host(&format!("{addr}:9999"), 2022).unwrap();
        assert_eq!(d.host, addr);
        assert_eq!(d.port, 9999);
    }

    #[test]
    fn positional_rejects_bad_colon_count() {
        assert!(parse_positional_host("a:b:c", 2022).is_err());
    }

    #[test]
    fn positional_rejects_bad_port() {
        assert!(parse_positional_host("host:notaport", 2022).is_err());
        assert!(parse_positional_host("host:99999", 2022).is_err());
    }

    #[test]
    fn positional_default_port_applies() {
        let d = parse_positional_host("host", 2022).unwrap();
        assert_eq!(d.port, 2022);
    }
}
