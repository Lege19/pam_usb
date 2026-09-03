use std::ffi::{CStr, c_char, c_int};

/// # SAFETY
/// `argv` points to an array of `argc` pointers to nul terminated strings
pub unsafe fn convert_args<'a>(
    argc: c_int,
    argv: *mut *const c_char,
) -> impl Iterator<Item = &'a CStr> {
    unsafe { std::slice::from_raw_parts(argv, argc as usize) }
        .iter()
        .map(|ptr| unsafe { CStr::from_ptr(*ptr) })
}

pub fn convert_result(result: Result<(), impl Into<c_int>>) -> c_int {
    match result {
        Ok(()) => pam_sys::PAM_SUCCESS,
        Err(e) => e.into(),
    }
}

macro_rules! gen_ffi {
    ($module:ty /* : Module */) => {
        mod ffi {
            use super::*;

            // SAFETY: These functions are all private, and so it is impossible for them to be
            // called from Rust.
            // Therefore they will only be called by PAM, which should provide the required
            // invariants.

            #[unsafe(no_mangle)]
            unsafe extern "C" fn pam_sm_authenticate(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_authenticate(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::Authenticate::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "C" fn pam_sm_setcred(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_setcred(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::Setcred::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "C" fn pam_sm_acct_mgmt(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_acct_mgmt(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::AcctMgmt::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "C" fn pam_sm_open_session(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_open_session(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::Session::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_close_session(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_close_session(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::Session::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "C" fn pam_sm_chauthtok(
                pamh: *mut ::pam_sys::pam_handle_t,
                flags: ::core::ffi::c_int,
                argc: ::core::ffi::c_int,
                argv: *mut *const ::core::ffi::c_char,
            ) -> ::core::ffi::c_int {
                crate::ffi::convert_result(
                    <$module as crate::pam_wrappers::Module>::pam_sm_chauthtok(
                        unsafe { pamh.as_mut_unchecked() },
                        crate::pam_wrappers::flags::Chauthtok::from_bits_retain(flags),
                        unsafe { crate::ffi::convert_args(argc, argv) },
                    ),
                )
            }
        }
    };
}

pub(crate) use gen_ffi;
