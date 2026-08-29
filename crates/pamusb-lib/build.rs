const DEFAULT_PAMUSB_HOME: &str = "/etc/security/pamusb";
const DEFAULT_PAMUSB_CHECK_PATH: &str = "/usr/sbin/__pamusb-check";

fn env_var(name: &str) -> Option<String> {
    println!("cargo::rerun-if-env-changed={}", name);
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(other) => {
            panic!("Failed to get environment variable {}: {}", name, other)
        }
    }
}

fn main() {
    let pamusb_home = env_var("PAMUSB_HOME");
    let pamusb_home = pamusb_home.as_deref().unwrap_or(DEFAULT_PAMUSB_HOME);
    println!("cargo::rustc-env=PAMUSB_HOME={}", pamusb_home);

    let pamusb_check_path = env_var("PAMUSB_CHECK_PATH");
    let pamusb_check_path = pamusb_check_path
        .as_deref()
        .unwrap_or(DEFAULT_PAMUSB_CHECK_PATH);
    println!("cargo::rustc-env=PAMUSB_CHECK_PATH={}", pamusb_check_path);

    let pamusb_config_path = format!("{}/pamusb.toml", pamusb_home);
    println!("cargo::rustc-env=PAMUSB_CONFIG_PATH={}", pamusb_config_path);
}
