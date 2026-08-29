use std::io::Write;

pub struct Logger;
impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if log::max_level() >= log::Level::Debug {
            eprintln!(
                "({}) {}: {}",
                record.target(),
                record.level(),
                record.args()
            );
        } else {
            eprintln!("{}: {}", record.level(), record.args());
        }
    }
    fn flush(&self) {
        _ = std::io::stdout().flush();
    }
}
