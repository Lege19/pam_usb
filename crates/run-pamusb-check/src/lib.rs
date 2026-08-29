use std::io;

use pamusb_lib::libc_wrappers;

pub fn run_pamusb_check(user: &str, debug: bool) -> io::Result<bool> {
    if debug && libc_wrappers::getuid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "You must run as root to debug pamusb-check",
        ));
    }
    std::process::Command::new(pamusb_lib::constants::PAMUSB_CHECK_PATH)
        .arg(user)
        .arg(if debug { "DEBUG" } else { "OFF" })
        .status()
        .map(|status| status.success())
}
