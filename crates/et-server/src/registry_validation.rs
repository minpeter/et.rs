use std::sync::Arc;

use et_core::keys::passkey_to_key;
use et_core::proto::TerminalUserInfo;

use crate::registry::{Registration, RegistrationError};

const ID_LEN: usize = 16;

pub(crate) fn validate(user_info: TerminalUserInfo) -> Result<Registration, RegistrationError> {
    let id = user_info.id.ok_or(RegistrationError::Invalid)?;
    if id.len() != ID_LEN || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(RegistrationError::Invalid);
    }
    let passkey = user_info.passkey.ok_or(RegistrationError::Invalid)?;
    let key = passkey_to_key(&passkey).ok_or(RegistrationError::Invalid)?;
    let uid = user_info
        .uid
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RegistrationError::Invalid)?;
    let gid = user_info
        .gid
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RegistrationError::Invalid)?;
    Ok(Registration {
        id,
        key,
        uid,
        gid,
        identity: Arc::new(()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TerminalUserInfo {
        TerminalUserInfo {
            id: Some("aaaaaaaaaaaaaaaa".to_owned()),
            passkey: Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_owned()),
            uid: Some(501),
            gid: Some(20),
            fd: None,
        }
    }

    #[test]
    fn identical_material_has_distinct_registration_generations() {
        let first = validate(info()).unwrap();
        let second = validate(info()).unwrap();
        assert_eq!(first, second);
        assert!(!first.same_generation(&second));
        assert!(!first.identity().same_generation(&second.identity()));
    }
}
