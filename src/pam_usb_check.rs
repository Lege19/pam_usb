#![warn(clippy::unwrap_used)]
use std::{
    ffi::{OsStr, OsString},
    io::{self, Read},
    ops::ControlFlow,
    path::Path,
    process::ExitCode,
};

use pam_usb::{
    key::Key,
    libc_wrappers::{self},
    vio,
};

fn print_help(name: Option<&str>) {
    eprintln!(
        "Usage: {} [--help] [--debug] [--config=path] [--dump] [--quiet] [--version] <username>",
        name.unwrap_or("pam_usb_check"),
    );
}

#[derive(Default)]
struct CliOptions {
    config_path: Option<String>,
    user: String,
}

fn parse_args() -> ControlFlow<ExitCode, CliOptions> {
    let mut args = std::env::args();
    let binary_name = args.next();
    let mut config_path: Option<String> = None;
    let mut user: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(binary_name.as_deref());
                return ControlFlow::Break(ExitCode::SUCCESS);
            }
            "-c" | "--config" => {
                if let Some(path) = args.next() {
                    if config_path.is_some() {
                        log::error!("--config argument given multiple times");
                        return ControlFlow::Break(ExitCode::FAILURE);
                    } else {
                        config_path = Some(path);
                    }
                } else {
                    log::error!("Expected config file path");
                    return ControlFlow::Break(ExitCode::FAILURE);
                }
            }
            "-D" | "--debug" => log::set_max_level(log::LevelFilter::Debug),
            "-q" | "--quiet" => log::set_max_level(log::LevelFilter::Debug),
            _ => {
                if args.next().is_some() {
                    log::error!("Unrecognised argument {}", arg);
                    return ControlFlow::Break(ExitCode::FAILURE);
                } else {
                    user = Some(arg);
                }
            }
        }
    }
    let Some(user) = user else {
        log::error!("Missing argument <username>");
        return ControlFlow::Break(ExitCode::FAILURE);
    };
    let options = CliOptions { config_path, user };
    ControlFlow::Continue(options)
}

fn main() -> ExitCode {
    let Ok(_) = log::set_logger(&pam_usb::logger::Logger) else {
        log::error!("Failed to initialise logging");
        return ExitCode::FAILURE;
    };
    log::set_max_level(log::LevelFilter::Info);
    let cli_options = match parse_args() {
        ControlFlow::Continue(cli_options) => cli_options,
        ControlFlow::Break(exit_code) => return exit_code,
    };
    match usb_check(cli_options, &mut vio::StdFs, &mut vio::Getrandom) {
        Ok(success) => {
            println!("{}", success);
            ExitCode::FAILURE
        }
        Err(error) => {
            log::error!("{}", error);
            ExitCode::FAILURE
        }
    }
}

#[derive(serde::Deserialize)]
struct Config {
    users: std::collections::HashMap<String, PerUserConfig>,
}
#[derive(serde::Deserialize)]
struct PerUserConfig {
    #[serde(rename = "device")]
    devices: Vec<DeviceConfig>,
}
#[derive(serde::Deserialize)]
struct DeviceConfig {
    uuid: String,
}

#[derive(Debug, thiserror::Error)]
enum UsbCheckError {
    #[error("Failed to read config file: {0}")]
    FailedToReadConfigFile(io::Error),
    #[error("Failed to parse config file: {0}")]
    BadConfig(toml::de::Error),
    #[error("Failed to read key: {0}")]
    FailedToReadKey(std::io::Error),
    #[error("pam_usb expects a UTF-8 hostname: {0}")]
    InvalidHostname(std::str::Utf8Error),
    #[error("Failed to mount partition: {0}")]
    MountFailed(io::Error),
    #[error("Failed to generate new key(s): {0}")]
    KeygenError(io::Error),
    #[error("Uncategorised io error: {0}")]
    OtherIo(#[from] io::Error),
}

fn get_config<P: AsRef<Path>>(config_path: P) -> Result<Config, UsbCheckError> {
    let mut config_file =
        std::fs::File::open(config_path).map_err(UsbCheckError::FailedToReadConfigFile)?;
    let mut config_buf = Vec::<u8>::new();
    config_file
        .read_to_end(&mut config_buf)
        .map_err(UsbCheckError::FailedToReadConfigFile)?;
    let config =
        toml::from_slice::<Config>(config_buf.as_slice()).map_err(UsbCheckError::BadConfig)?;
    log::debug!("Successfully read and parsed config file");
    Ok(config)
}

fn usb_check(
    cli_options: CliOptions,
    fs: &mut impl vio::Fs,
    rng: &mut impl vio::Rng,
) -> Result<bool, UsbCheckError> {
    let config_path = cli_options
        .config_path
        .expect("Need to specify config file path");
    let config = get_config(config_path)?;

    let Some(PerUserConfig { devices, .. }) = config.users.get(cli_options.user.as_str()) else {
        log::debug!("User {} has no entry in the config file", cli_options.user);
        return Ok(false);
    };

    let uuids: Vec<&str> = devices
        .iter()
        .map(|device_config| device_config.uuid.as_str())
        .collect();

    let hostname = libc_wrappers::gethostname()?;
    let hostname = hostname.to_str().map_err(UsbCheckError::InvalidHostname)?;

    let Some(partition) = find_partition_by_uuids(uuids.as_slice())? else {
        log::debug!("Failed to find a partition with one of the listed uuids",);
        return Ok(false);
    };

    let mount = fs
        .mount(partition.devnode, partition.fs_type.as_os_str())
        .map_err(UsbCheckError::MountFailed)?;
    log::debug!("Successfully mounted a relevant partition");

    let system_key_path = std::path::Path::new("/etc/security/pamusb")
        .join(format!("{}.{}.key", cli_options.user, partition.uuid));
    let device_key_path = mount
        .as_ref()
        .join(format!(".pamusb/{}.{}.key", cli_options.user, hostname));
    log::debug!("Looking for system key at {:?}", system_key_path);
    log::debug!("Looking for device key at {:?}", device_key_path);

    let mut system_key = Key::zeroes();
    system_key
        .read_from_file(fs, system_key_path.as_path())
        .map_err(UsbCheckError::FailedToReadKey)?;
    let mut device_key = Key::zeroes();
    device_key
        .read_from_file(fs, device_key_path.as_path())
        .map_err(UsbCheckError::FailedToReadKey)?;

    if !Key::check(&system_key, &device_key) {
        return Ok(false);
    }

    Key::regenerate_key_pair(&mut system_key, &mut device_key, rng)
        .map_err(UsbCheckError::KeygenError)?;
    system_key.write_to_file(fs, system_key_path.as_path())?;
    device_key.write_to_file(fs, device_key_path.as_path())?;

    Ok(true)
}

struct Partition<'uuid> {
    devnode: OsString,
    fs_type: OsString,
    uuid: &'uuid str,
}

fn find_partition_by_uuids<'uuid>(
    uuids: &[&'uuid str],
) -> std::io::Result<Option<Partition<'uuid>>> {
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("block")?;
    for device in enumerator.scan_devices()? {
        if device.devtype() == Some(OsStr::new("partition"))
            && let Some(haystack_uuid) = device.property_value("PARTUUID")
            && let Some(uuid) = uuids
                .iter()
                .find(|needle_uuid| **needle_uuid == haystack_uuid)
            && let Some(devnode) = device.devnode()
            && let devnode = devnode.to_owned().into_os_string()
            && let Some(id_fs_type) = device.property_value("ID_FS_TYPE")
            && let fs_type = id_fs_type.to_owned()
        {
            return Ok(Some(Partition {
                devnode,
                fs_type,
                uuid,
            }));
        }
    }
    Ok(None)
}
