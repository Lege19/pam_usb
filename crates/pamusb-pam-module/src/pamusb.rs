use crate::{
    ffi::gen_ffi,
    pam_wrappers::{self, Module, errors, flags},
};
use pam_sys::pam_handle_t as Handle;

pub struct Pamusb;

impl Module for Pamusb {
    fn pam_sm_authenticate<'a>(
        pamh: &mut Handle,
        _flags: flags::Authenticate,
        _args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Authenticate> {
        use errors::Authenticate::*;
        let user = pam_wrappers::get_user(pamh, None)
            .map_err(|_| PAM_AUTH_ERR)?
            .map_err(|_| PAM_USER_UNKNOWN)?
            .to_str()
            .map_err(|_| PAM_USER_UNKNOWN)?;

        if run_pamusb_check::run_pamusb_check(user, false).map_err(|_| PAM_AUTH_ERR)? {
            Ok(())
        } else {
            Err(PAM_AUTHINFO_UNAVAIL)
        }
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
        // probably safe in case of misconfiguration
        Err(errors::AcctMgmt::PAM_PERM_DENIED)
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
        pamh: &mut Handle,
        flags: flags::Chauthtok,
        args: impl Iterator<Item = &'a std::ffi::CStr>,
    ) -> Result<(), errors::Chauthtok> {
        Ok(())
    }
}

gen_ffi!(Pamusb);
