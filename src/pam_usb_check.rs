#![warn(clippy::unwrap_used)]
use std::{
    ffi::{OsStr, OsString},
    io::Read,
    ops::ControlFlow,
    path::Path,
    process::ExitCode,
};

use rustix::mount::{MountFlags, UnmountFlags};

/// in bytes
const KEY_LEGNTH: usize = 1024;
type Key = [u8; KEY_LEGNTH];

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
    match usb_check(cli_options) {
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

fn errno_to_io_error(errno: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno.raw_os_error())
}

#[derive(Debug, thiserror::Error)]
enum UsbCheckError {
    #[error("Failed to parse config file: {0}")]
    MalformedConfig(#[from] toml::de::Error),
    #[error("Io operation failed: {0}")]
    IoError(#[from] std::io::Error),
    #[error("pam_usb expects a UTF-8 hostname: {0}")]
    InvalidHostname(std::str::Utf8Error),
    #[error("A key file was the wrong length")]
    WrongLengthKey,
}

fn get_config<P: AsRef<Path>>(config_path: P) -> Result<Config, UsbCheckError> {
    let mut config_file = std::fs::File::open(config_path)?;
    let mut config_buf = Vec::<u8>::new();
    config_file.read_to_end(&mut config_buf)?;
    let config = toml::from_slice::<Config>(config_buf.as_slice())?;
    log::debug!("Successfully read and parsed config file");
    Ok(config)
}

fn with_tmp_mount<R>(
    partition: &Partition<'_>,
    run: impl FnOnce(&Path) -> R,
) -> std::io::Result<R> {
    let mount_point = tempfile::tempdir()?;
    log::debug!("Mounting partition at {:?}", partition.devnode);
    rustix::mount::mount(
        partition.devnode.as_os_str(),
        mount_point.path(),
        partition.fs_type.as_os_str(),
        // Disable as much room for edge cases as possible
        MountFlags::DIRSYNC
            | MountFlags::SYNCHRONOUS
            | MountFlags::NODEV
            | MountFlags::NOEXEC
            | MountFlags::NOSUID
            | MountFlags::NOSYMFOLLOW,
        None,
    )
    .map_err(errno_to_io_error)?;
    log::debug!("Successfully mounted partition to {:?}", mount_point.path());

    let r = run(mount_point.path());

    rustix::mount::unmount(
        mount_point.path(),
        UnmountFlags::DETACH | UnmountFlags::NOFOLLOW,
    )
    .map_err(errno_to_io_error)?;

    Ok(r)
}

fn usb_check(cli_options: CliOptions) -> Result<bool, UsbCheckError> {
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

    let Some(partition) = find_partition_by_uuids(uuids.as_slice())? else {
        log::debug!("Failed to find a partition with one of the listed uuids",);
        return Ok(false);
    };

    with_tmp_mount(&partition, |mount_path| {
        let uname = rustix::system::uname();
        let hostname = match uname.nodename().to_str() {
            Ok(hostname) => hostname,
            Err(err) => {
                return Err(UsbCheckError::InvalidHostname(err));
            }
        };

        let system_key_path = std::path::Path::new("/etc/security/pamusb")
            .join(format!("{}.{}.key", cli_options.user, partition.uuid));
        let device_key_path =
            mount_path.join(format!(".pamusb/{}.{}.key", cli_options.user, hostname));
        log::debug!("Looking for system key at {:?}", system_key_path);
        log::debug!("Looking for device key at {:?}", device_key_path);

        let system_key = read_key(system_key_path)?;
        let device_key = read_key(device_key_path)?;

        Ok(check_keys(&system_key, &device_key))
    })?
}
fn read_key(path: impl AsRef<Path>) -> Result<Key, UsbCheckError> {
    let mut key_file = std::fs::File::open(path)?;
    check_key_file_length(&key_file)?;
    let mut key: Key = [0; _];
    key_file.read_exact(&mut key)?;
    Ok(key)
}
fn check_key_file_length(file: &std::fs::File) -> Result<(), UsbCheckError> {
    if file.metadata()?.len() != KEY_LEGNTH as u64 {
        Err(UsbCheckError::WrongLengthKey)
    } else {
        Ok(())
    }
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

fn check_keys(system_key: &Key, device_key: &Key) -> bool {
    system_key == device_key
}
