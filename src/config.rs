use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;

/// DNSConfig holds the mapping of domain names (and wildcards) to IP addresses,
/// as well as the fallback DNS server address.
#[derive(Deserialize, Debug)]
pub struct DNSConfig {
    pub records: HashMap<String, String>,
    pub fallback_dns: String,
}

/// Load the DNS configuration from a JSON file.
/// The file should contain a JSON object matching the DNSConfig structure.
pub fn load_config(file_path: &str) -> Result<DNSConfig, Box<dyn Error>> {
    let data = fs::read_to_string(file_path)?;
    let config: DNSConfig = serde_json::from_str(&data)?;
    Ok(config)
}
