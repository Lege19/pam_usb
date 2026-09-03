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
}

gen_ffi!(Pamusb);
