use et_core::keys::passkey_to_key;

const ID_LEN: usize = 16;
const PASSKEY_LEN: usize = 32;
const MAX_TERM_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialInput {
    pub id: String,
    pub passkey: String,
    pub term: String,
}

pub fn parse_credential_input(value: &str) -> Result<CredentialInput, String> {
    let (credentials, term) = value
        .split_once('_')
        .ok_or_else(|| "expected id/passkey_TERM".to_owned())?;
    let (id, passkey) = credentials
        .split_once('/')
        .ok_or_else(|| "expected id/passkey_TERM".to_owned())?;
    if id.len() != ID_LEN || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("session id must be 16 ASCII-alphanumeric bytes".to_owned());
    }
    if passkey.len() != PASSKEY_LEN
        || !passkey.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || passkey_to_key(passkey).is_none()
    {
        return Err("passkey must be 32 ASCII-alphanumeric bytes".to_owned());
    }
    if term.is_empty()
        || term.len() > MAX_TERM_LEN
        || !term
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("TERM contains unsupported characters or length".to_owned());
    }
    Ok(CredentialInput {
        id: id.to_owned(),
        passkey: passkey.to_owned(),
        term: term.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "abcdefghijklmnop";
    const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

    #[test]
    fn parses_bootstrap_input() {
        assert_eq!(
            parse_credential_input(&format!("{ID}/{KEY}_xterm-256color")).unwrap(),
            CredentialInput {
                id: ID.to_owned(),
                passkey: KEY.to_owned(),
                term: "xterm-256color".to_owned(),
            }
        );
    }

    #[test]
    fn rejects_malformed_credentials_and_term() {
        for value in [
            "",
            "bad",
            "short/key_xterm",
            "abcdefghijklmnop/short_xterm",
            "abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_bad term",
        ] {
            assert!(parse_credential_input(value).is_err(), "{value}");
        }
    }
}
