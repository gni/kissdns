use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// DNSConfig holds the mapping of domain names (and wildcards) to IP addresses,
/// as well as the fallback DNS server address.
#[derive(Deserialize, Debug)]
pub struct DNSConfig {
    pub records: HashMap<String, String>,
    pub fallback_dns: String,
}

/// The default configuration
const DEFAULT_CONFIG: &str = r#"
{
  "records": {
    "dev.kiss.dns": "127.0.0.1",
    "api.kiss.dns": "127.0.0.2",
    "*.test.kiss.dns": "127.0.0.3",
    "ipv6.kiss.dns": "fe80::6049:67ff:fedb:e84d"
  },
  "fallback_dns": "8.8.8.8"
}
"#;

/// Load the DNS configuration from a JSON file.
/// If the file does not exist, a default configuration file is created and the user is informed.
pub fn load_config(file_path: &str) -> Result<DNSConfig, Box<dyn Error>> {
    if !Path::new(file_path).exists() {
        println!("Configuration file '{}' not found. Creating default configuration.", file_path);
        let mut file = OpenOptions::new().write(true).create(true).open(file_path)?;
        file.write_all(DEFAULT_CONFIG.as_bytes())?;
        file.flush()?;
        println!("Default configuration file '{}' created.", file_path);
    }
    let data = fs::read_to_string(file_path)?;
    let config: DNSConfig = serde_json::from_str(&data)?;
    Ok(config)
}
