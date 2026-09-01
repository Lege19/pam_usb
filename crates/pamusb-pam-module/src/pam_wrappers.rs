use pam_sys::pam_handle_t as Handle;
use std::{
    ffi::{CStr, c_char},
    ptr::null,
};

pub enum CriticalError {
    InvalidEnumVariant,
}

pub mod flags {
    use pam_sys::*;
    wrapper_utils::decl_bitflags! {
        repr = core::ffi::c_int;

        Authenticate { PAM_SILENT, PAM_DISALLOW_NULL_AUTHTOK }
        Setcred {
            PAM_SILENT,
            PAM_ESTABLISH_CRED,
            PAM_DELETE_CRED,
            PAM_REINITIALIZE_CRED,
            PAM_REFRESH_CRED
        }
        AcctMgmt { PAM_SILENT, PAM_DISALLOW_NULL_AUTHTOK }
        Session { PAM_SILENT }
        Chauthtok {
            PAM_SILENT,
            PAM_CHANGE_EXPIRED_AUTHTOK,
            PAM_PRELIM_CHECK,
            PAM_UPDATE_AUTHTOK,
        }
    }
}

pub mod errors {
    use pam_sys::*;
    wrapper_utils::decl_enums! {
        repr = i32;

        Authenticate {
            PAM_AUTH_ERR,
            PAM_CRED_INSUFFICIENT,
            PAM_AUTHINFO_UNAVAIL,
            PAM_USER_UNKNOWN,
            PAM_MAXTRIES,
        }
        Setcred {
            PAM_CRED_UNAVAIL,
            PAM_CRED_EXPIRED,
            PAM_CRED_ERR,
            PAM_USER_UNKNOWN,
        }
        AcctMgmt {
            PAM_ACCT_EXPIRED,
            PAM_AUTH_ERR,
            PAM_NEW_AUTHTOK_REQD,
            PAM_PERM_DENIED,
            PAM_USER_UNKNOWN,
        }
        Session {
            PAM_SESSION_ERR,
        }
        Chauthtok {
            PAM_AUTHTOK_ERR,
            PAM_AUTHTOK_RECOVERY_ERR,
            PAM_AUTHTOK_LOCK_BUSY,
            PAM_AUTHTOK_DISABLE_AGING,
            PAM_PERM_DENIED,
            PAM_TRY_AGAIN,
            PAM_USER_UNKNOWN,
        }
        GetUser {
            PAM_SYSTEM_ERR,
            PAM_CONV_ERR,
            PAM_BUF_ERR,
            PAM_ABORT,
        }
    }
}

pub trait Module {
    fn pam_sm_authenticate<'a>(
        pamh: &mut Handle,
        flags: flags::Authenticate,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Authenticate>;

    fn pam_sm_setcred<'a>(
        pamh: &mut Handle,
        flags: flags::Setcred,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Setcred>;

    fn pam_sm_acct_mgmt<'a>(
        pamh: &mut Handle,
        flags: flags::AcctMgmt,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::AcctMgmt>;

    fn pam_sm_open_session<'a>(
        pamh: &mut Handle,
        flags: flags::Session,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Session>;

    fn pam_sm_close_session<'a>(
        pamh: &mut Handle,
        flags: flags::Session,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Session>;

    fn pam_sm_chauthtok<'a>(
        pamh: &mut Handle,
        flags: flags::Chauthtok,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Chauthtok>;
}

pub fn get_user<'a>(
    pamh: &'a mut Handle,
    prompt: Option<&CStr>,
) -> Result<Result<&'a CStr, errors::GetUser>, CriticalError> {
    loop {
        let mut out: *const c_char = null();
        use std::ptr;
        let prompt = prompt.map_or_else(ptr::null, CStr::as_ptr);
        let status = unsafe { pam_sys::pam_get_user(pamh, &mut out as *mut *const c_char, prompt) };
        return match status {
            pam_sys::PAM_SUCCESS => Ok(Ok(unsafe { CStr::from_ptr(out) })),
            pam_sys::PAM_CONV_AGAIN => continue,
            other => other
                .try_into()
                .map_err(|_| CriticalError::InvalidEnumVariant)
                .map(Err),
        };
    }
}
