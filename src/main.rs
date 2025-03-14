mod dns_handler;
mod config;

use dns_handler::DNSHandler;
use config::load_config;
use std::env;
use std::process;
use ctrlc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() {
    // Initialize logging (set RUST_LOG=info to see info logs)
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    // Determine configuration file and port based on the provided arguments.
    let (config_path, port) = match args.len() {
        1 => ("hosts.json".to_string(), "5533".to_string()),
        2 => {
            // If one argument (besides program name) is provided, check if it's numeric.
            if args[1].parse::<u16>().is_ok() {
                ("hosts.json".to_string(), args[1].clone())
            } else {
                (args[1].clone(), "5533".to_string())
            }
        }
        _ => (args[1].clone(), args[2].clone()),
    };

    log::info!("Starting DNS server on port: {}", port);
    log::info!("Loading configuration from: {}", config_path);

    // Load configuration from the provided config file.
    let config = match load_config(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Create a shutdown flag and register a Ctrl+C handler for graceful shutdown.
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    {
        let shutdown_flag = Arc::clone(&shutdown_flag);
        ctrlc::set_handler(move || {
            log::info!("Shutdown signal received");
            shutdown_flag.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    // Create the DNS handler passing in configuration and the shutdown flag.
    let handler = DNSHandler::new(config, shutdown_flag.clone());
    handler.start(&port);
}
