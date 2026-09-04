use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
#[derive(Parser)]
#[command(name = "pamusb")]
#[command(version, about, long_about=None)]
struct Cli {
    #[command(flatten)]
    log_level: LogLevel,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
#[group(multiple = false)]
struct LogLevel {
    /// Enable extra logging to help with debugging/setup.
    #[arg(long, global = true)]
    debug: bool,
    #[arg(long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Check(Check),
}
#[derive(Args)]
struct Check {
    #[arg(name = "USER")]
    user: String,
}
impl Check {
    fn run(&self, debug: bool) -> ExitCode {
        let success = match run_pamusb_check::run_pamusb_check(self.user.as_str(), debug) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{e}");
                false
            }
        };
        if success {
            println!("Successfully authenticated {}", self.user);
            ExitCode::SUCCESS
        } else {
            println!("Failed to authenticated {}", self.user);
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    log::set_logger(&pamusb_lib::logger::Logger).expect("set_logger is only called once");
    if cli.log_level.quiet {
        log::set_max_level(log::LevelFilter::Off);
    }
    if cli.log_level.debug {
        log::set_max_level(log::LevelFilter::Debug);
    }
    match cli.command {
        Commands::Check(check) => check.run(cli.log_level.debug),
    }
}
