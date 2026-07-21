mod config;
mod dns_handler;

use config::load_config;
use dns_handler::DNSHandler;
use std::env;
use std::process;
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

    // On Unix, SIGHUP requests a configuration reload. The signal handler only
    // updates an atomic flag; parsing and applying the configuration happens in
    // the server loop, outside of the signal context.
    let reload_flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    if let Err(e) = signal_hook::flag::register(
        signal_hook::consts::signal::SIGHUP,
        Arc::clone(&reload_flag),
    ) {
        log::error!("Failed to register SIGHUP handler: {}", e);
        process::exit(1);
    }

    // Create the DNS handler passing in configuration and the signal flags.
    let handler = DNSHandler::new(config, config_path, shutdown_flag, reload_flag);
    handler.start(&port);
}
