//! Runtime interface:
//! stdin and stdout are not used for anything
//! - argv[0] is ignored
//! - argv[1] is the username of the user to authenticate
//! - argv[2] is the log level, this is only allowed to be anything other than OFF if run as root.
//!   The options match [`log::LevelFilter`].
//!   It's not case sensitive.

#![warn(clippy::unwrap_used)]
use std::{
    io,
    process::ExitCode,
    str::{FromStr, Utf8Error},
};

use pamusb_lib::{key::Key, libc_wrappers, vio};

fn main() -> ExitCode {
    // Remove this potential attack vector
    if std::env::vars_os().next().is_none() {
        return ExitCode::FAILURE;
    }
    let mut args = std::env::args();
    if let Some(_binary_name) = args.next()
        && let Some(user) = args.next()
        && let Some(debug) = args.next()
        && let None = args.next()
    {
        let Ok(log_level) = log::LevelFilter::from_str(debug.as_str()) else {
            return ExitCode::FAILURE;
        };
        // You should only be allowed to debug as root,
        // since debug logs might leak sensitive info
        if log_level != log::LevelFilter::Off && libc_wrappers::getuid() != 0 {
            return ExitCode::FAILURE;
        }
        log::set_max_level(log_level);
        log::set_logger(&pamusb_lib::logger::Logger).expect("set_logger is only called once");

        match usb_check(user.as_str(), &mut vio::StdFs, &mut vio::Getrandom) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                log::error!("{e}");
                ExitCode::FAILURE
            }
        }
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Debug, thiserror::Error)]
enum UsbCheckError {
    #[error("{msg}: {source}")]
    IoError {
        msg: &'static str,
        source: io::Error,
    },
    #[error("Bad hostname")]
    InvalidHostname(#[source] Utf8Error),
}
impl UsbCheckError {
    fn with_msg(msg: &'static str) -> impl Fn(io::Error) -> UsbCheckError {
        move |err| UsbCheckError::IoError { msg, source: err }
    }
}
fn usb_check(
    user: &str,
    fs: &mut impl vio::Fs,
    rng: &mut impl vio::Rng,
) -> Result<bool, UsbCheckError> {
    let config = pamusb_lib::config::get_config(pamusb_lib::constants::PAMUSB_CONFIG_PATH)
        .map_err(UsbCheckError::with_msg("Failed to get config"))?;

    let Some(per_user_config) = config.users.get(user) else {
        log::debug!("User \"{}\" has no entry in the config file", user);
        return Ok(false);
    };
    let uuids: Vec<&str> = per_user_config
        .devices
        .iter()
        .map(|device_config| device_config.uuid.as_str())
        .collect();

    let hostname =
        libc_wrappers::gethostname().map_err(UsbCheckError::with_msg("Failed to get hostname"))?;
    let hostname = hostname.to_str().map_err(UsbCheckError::InvalidHostname)?;

    let Some(partition) = pamusb_lib::partition::find_partition_by_uuids(uuids.as_slice())
        .map_err(UsbCheckError::with_msg(
            "Error searching for relevant partition",
        ))?
    else {
        log::debug!("Failed to find a partition with one of the listed uuids",);
        return Ok(false);
    };

    let mount = fs
        .mount(partition.devnode, partition.fs_type.as_os_str())
        .map_err(UsbCheckError::with_msg("Failed to mount partition"))?;
    log::debug!("Successfully mounted a relevant partition");

    let system_key_path = std::path::Path::new("/etc/security/pamusb")
        .join(format!("{}.{}.key", user, partition.uuid));
    let device_key_path = mount
        .as_ref()
        .join(format!(".pamusb/{}.{}.key", user, hostname));
    log::debug!("Looking for system key at {:?}", system_key_path);
    log::debug!("Looking for device key at {:?}", device_key_path);

    let mut system_key = Key::zeroes();
    system_key
        .read_from_file(fs, system_key_path.as_path())
        .map_err(UsbCheckError::with_msg("Failed to read system key"))?;
    let mut device_key = Key::zeroes();
    device_key
        .read_from_file(fs, device_key_path.as_path())
        .map_err(UsbCheckError::with_msg("Failed to read device key"))?;

    if !Key::check(&system_key, &device_key) {
        return Ok(false);
    }

    Key::regenerate_key_pair(&mut system_key, &mut device_key, rng)
        .map_err(UsbCheckError::with_msg("Failed to generate keys"))?;
    system_key
        .write_to_file(fs, system_key_path.as_path())
        .map_err(UsbCheckError::with_msg("Failed to update system key file"))?;
    device_key
        .write_to_file(fs, device_key_path.as_path())
        .map_err(UsbCheckError::with_msg("Failed to update device key file"))?;

    Ok(true)
}
