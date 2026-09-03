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
    #![allow(unused)]

    fn pam_sm_authenticate<'a>(
        pamh: &mut Handle,
        flags: flags::Authenticate,
        args: impl Iterator<Item = &'a CStr>,
    ) -> Result<(), errors::Authenticate> {
        Err(errors::Authenticate::PAM_AUTH_ERR)
    }
    fn pam_sm_setcred<'a>(
        pamh: &mut Handle,
        flags: flags::Setcred,
        args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Setcred> {
        Ok(())
    }
    fn pam_sm_acct_mgmt<'a>(
        pamh: &mut Handle,
        flags: flags::AcctMgmt,
        args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::AcctMgmt> {
        Ok(())
    }
    fn pam_sm_open_session<'a>(
        pamh: &mut Handle,
        flags: flags::Session,
        args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Session> {
        Ok(())
    }
    fn pam_sm_close_session<'a>(
        pamh: &mut Handle,
        flags: flags::Session,
        args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Session> {
        Ok(())
    }
    fn pam_sm_chauthtok<'a>(
        _pamh: &mut Handle,
        _flags: flags::Chauthtok,
        _args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Chauthtok> {
        Ok(())
    }
}

// The man pages do not clearly document the lifetime of the returned string.
// I think tying this to the lifetime of the pam handle should be playing it safe,
// since it shouldn't be possible to obtain a reference to a pam handle with a longer lifetime than
// a call to any single pam module function.
pub fn get_user<'a>(
    pamh: &'a mut Handle,
    prompt: Option<&CStr>,
) -> Result<Result<&'a CStr, errors::GetUser>, CriticalError> {
    loop {
        let mut out: *const c_char = null();
        use std::ptr;
        let prompt = prompt.map_or_else(ptr::null, CStr::as_ptr);
        // SAFETY: pamh is a valid pointer to a pam handle, since it came from a Rust reference.
        // out is mutable, and is a *const c_char (the right type), and won't be accessed
        // concurrently by other code.
        let status = unsafe { pam_sys::pam_get_user(pamh, &mut out as *mut *const c_char, prompt) };
        return match status {
            // SAFETY: If pam_get_user succeeded, then it would have written a pointer to a
            // c string to out.
            pam_sys::PAM_SUCCESS => Ok(Ok(unsafe { CStr::from_ptr(out) })),
            pam_sys::PAM_CONV_AGAIN => continue,
            other => other
                .try_into()
                .map_err(|_| CriticalError::InvalidEnumVariant)
                .map(Err),
        };
    }
}
