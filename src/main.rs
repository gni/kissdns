mod dns_handler;
mod config;

use dns_handler::DNSHandler;
use config::load_config;
use std::env;
use std::process;

fn main() {
    // Initialize logging
    env_logger::init();

    let port = env::args().nth(1).unwrap_or_else(|| "5533".to_string());
    log::info!("Starting DNS server on port: {}", port);

    // Load configuration from a JSON file (e.g., hosts.json)
    let config = match load_config("hosts.json") {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Create DNSHandler with dynamic configuration (using RwLock for future management)
    let handler = DNSHandler::new(config);
    handler.start(&port);
}
