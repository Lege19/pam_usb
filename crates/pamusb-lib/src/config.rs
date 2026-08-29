use std::io::{self, Read};
use std::path::Path;

#[derive(serde::Deserialize)]
pub struct Config {
    pub users: std::collections::HashMap<String, PerUserConfig>,
}
#[derive(serde::Deserialize)]
pub struct PerUserConfig {
    #[serde(rename = "device")]
    pub devices: Vec<DeviceConfig>,
}
#[derive(serde::Deserialize)]
pub struct DeviceConfig {
    pub uuid: String,
}

pub fn get_config<P: AsRef<Path>>(config_path: P) -> io::Result<Config> {
    let mut config_file = std::fs::File::open(config_path)?;
    let mut config_buf = Vec::<u8>::new();
    config_file.read_to_end(&mut config_buf)?;
    let config = toml::from_slice::<Config>(config_buf.as_slice())
        .map_err(|parse_error| io::Error::new(io::ErrorKind::InvalidData, parse_error))?;
    log::debug!("Successfully read and parsed config file");
    Ok(config)
}
