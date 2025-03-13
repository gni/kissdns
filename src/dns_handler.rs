use crate::config::DNSConfig;
use log::{error, info, warn};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// DNSHandler is responsible for handling incoming DNS requests,
/// performing local record lookups, and forwarding queries to a fallback DNS server if needed.
pub struct DNSHandler {
    config: Arc<RwLock<DNSConfig>>,
}

impl DNSHandler {
    /// Create a new DNSHandler with the provided configuration.
    pub fn new(config: DNSConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Attempt to resolve the domain using local configuration records.
    /// Supports exact matches as well as wildcard patterns (e.g., "*.example.com").
    fn resolve_domain(&self, domain: &str) -> Option<Ipv4Addr> {
        let cfg = self.config.read().expect("Failed to acquire config read lock");
        if let Some(ip) = cfg.records.get(domain) {
            return ip.parse().ok();
        }
        // Support wildcard records: patterns starting with "*."
        for (pattern, ip) in &cfg.records {
            if pattern.starts_with("*.") && domain.ends_with(&pattern[1..]) {
                return ip.parse().ok();
            }
        }
        None
    }

    /// Start both UDP and TCP DNS servers on the given port.
    /// UDP processing happens on the main thread while TCP connections are handled in a separate thread.
    pub fn start(&self, port: &str) {
        let udp_address = format!("0.0.0.0:{}", port);
        let tcp_address = udp_address.clone();

        let udp_socket = match UdpSocket::bind(&udp_address) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind UDP socket on {}: {}", udp_address, e);
                return;
            }
        };
        info!("UDP DNS Server running on {}", udp_address);

        // Clone configuration for the TCP thread.
        let config_clone = Arc::clone(&self.config);
        std::thread::spawn(move || {
            let tcp_listener = match TcpListener::bind(&tcp_address) {
                Ok(listener) => listener,
                Err(e) => {
                    error!("Failed to bind TCP socket on {}: {}", tcp_address, e);
                    return;
                }
            };
            info!("TCP DNS Server running on {}", tcp_address);

            // Accept and handle TCP connections.
            for stream in tcp_listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let config = Arc::clone(&config_clone);
                        std::thread::spawn(move || handle_tcp_request(&mut stream, &config));
                    }
                    Err(e) => error!("Error accepting TCP connection: {}", e),
                }
            }
        });

        let mut buf = [0u8; 512];

        // Main UDP loop.
        loop {
            match udp_socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    if size < 12 {
                        warn!("Received malformed DNS request (too small) from {}", src);
                        continue;
                    }

                    if let Some(domain) = Self::extract_domain_name(&buf[..size]) {
                        let response = if let Some(ip) = self.resolve_domain(&domain) {
                            info!("[UDP] Resolving {} -> {}", domain, ip);
                            Self::build_dns_response(&buf[..size], ip)
                        } else {
                            let cfg = self.config.read().expect("Failed to read config");
                            if !cfg.fallback_dns.is_empty() {
                                // Forward query to the fallback DNS server.
                                match self.forward_udp_query(&buf[..size]) {
                                    Some(resp) => {
                                        info!("[UDP] Fallback resolution for {} succeeded", domain);
                                        resp
                                    }
                                    None => {
                                        info!("[UDP] Fallback resolution for {} failed, returning NXDOMAIN", domain);
                                        Self::build_nxdomain_response(&buf[..size])
                                    }
                                }
                            } else {
                                info!("[UDP] No record found for {}, returning NXDOMAIN", domain);
                                Self::build_nxdomain_response(&buf[..size])
                            }
                        };

                        if let Err(e) = udp_socket.send_to(&response, &src) {
                            error!("Failed to send DNS response to {}: {}", src, e);
                        }
                    } else {
                        warn!("Failed to extract domain name from request received from {}", src);
                    }
                }
                Err(e) => error!("Error receiving UDP request: {}", e),
            }
        }
    }

    /// Forward a UDP DNS query to the fallback DNS server.
    /// Returns the fallback server's response or None on failure.
    fn forward_udp_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        let cfg = self.config.read().expect("Failed to read config");
        let fallback_addr = if cfg.fallback_dns.contains(":") {
            cfg.fallback_dns.clone()
        } else {
            format!("{}:53", cfg.fallback_dns)
        };

        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        sock.send_to(query, &fallback_addr).ok()?;
        let mut buf = [0u8; 512];
        let (size, _) = sock.recv_from(&mut buf).ok()?;
        Some(buf[..size].to_vec())
    }

    /// Extract the queried domain name from a DNS request packet.
    /// Returns None if the extraction fails.
    fn extract_domain_name(request: &[u8]) -> Option<String> {
        let mut pos = 12;
        let mut labels = Vec::new();

        while pos < request.len() {
            let len = request[pos] as usize;
            if len == 0 {
                break;
            }
            if pos + len + 1 > request.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&request[pos + 1..pos + 1 + len]).into_owned());
            pos += len + 1;
        }

        if labels.is_empty() {
            None
        } else {
            Some(labels.join("."))
        }
    }

    /// Build a DNS response packet with an answer pointing to the given IPv4 address.
    fn build_dns_response(request: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::new();

        response.extend_from_slice(&request[..2]); // Transaction ID
        response.extend_from_slice(&[0x81, 0x80]); // Flags: Response, No Error
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT (1 question)
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT (1 answer)
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT

        // Copy the question section.
        let mut question_end = 12;
        while question_end < request.len() && request[question_end] != 0 {
            question_end += 1;
        }
        question_end += 5; // Skip the null byte and QTYPE/QCLASS

        response.extend_from_slice(&request[12..question_end]);

        // Answer: pointer to domain name at offset 0x0c.
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60 seconds
        response.extend_from_slice(&[0x00, 0x04]); // Data length (4 bytes)
        response.extend_from_slice(&ip.octets());

        response
    }

    /// Build a DNS response packet indicating an NXDOMAIN (non-existent domain) error.
    fn build_nxdomain_response(request: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();

        response.extend_from_slice(&request[..2]); // Transaction ID
        response.extend_from_slice(&[0x81, 0x83]); // Flags: QR (response), RCODE=3 (NXDOMAIN)
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT (1 question)
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT (0 answers)
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT

        // Copy the question section if available.
        let mut question_end = 12;
        while question_end < request.len() && request[question_end] != 0 {
            question_end += 1;
        }
        question_end += 5;
        if question_end <= request.len() {
            response.extend_from_slice(&request[12..question_end]);
        }

        response
    }
}

/// Handle a single TCP DNS request.
/// If a record is not found in the local config and fallback DNS is configured,
/// the request is forwarded to the fallback DNS server.
pub fn handle_tcp_request(stream: &mut TcpStream, config: &Arc<RwLock<DNSConfig>>) {
    let mut buffer = [0u8; 1024];

    match stream.read(&mut buffer) {
        Ok(size) => {
            if size < 2 {
                warn!("Received incomplete TCP request");
                return;
            }

            let query_size = ((buffer[0] as usize) << 8) | (buffer[1] as usize);
            if query_size + 2 > size {
                warn!("Malformed TCP request, query size mismatch");
                return;
            }

            // Get the full query (including the 2-byte length prefix).
            let query = &buffer[0..query_size + 2];
            if let Some(domain) = DNSHandler::extract_domain_name(&buffer[2..query_size + 2]) {
                let cfg = config.read().expect("Failed to acquire config lock");
                if let Some(ip) = cfg.records.get(&domain).and_then(|ip| ip.parse().ok()) {
                    info!("[TCP] Resolving {} -> {}", domain, ip);
                    let response_body = DNSHandler::build_dns_response(&buffer[2..query_size + 2], ip);
                    let mut full_response = vec![
                        (response_body.len() >> 8) as u8,
                        (response_body.len() & 0xFF) as u8,
                    ];
                    full_response.extend_from_slice(&response_body);
                    if let Err(e) = stream.write_all(&full_response) {
                        error!("Failed to send TCP response: {}", e);
                    }
                } else if !cfg.fallback_dns.is_empty() {
                    // Forward the TCP query to the fallback DNS server.
                    match forward_tcp_query(query, &cfg.fallback_dns) {
                        Some(fallback_response) => {
                            info!("[TCP] Fallback resolution for {} succeeded", domain);
                            if let Err(e) = stream.write_all(&fallback_response) {
                                error!("Failed to send TCP fallback response: {}", e);
                            }
                        }
                        None => {
                            info!("[TCP] Fallback resolution for {} failed, returning NXDOMAIN", domain);
                            let response_body = DNSHandler::build_nxdomain_response(&buffer[2..query_size + 2]);
                            let mut full_response = vec![
                                (response_body.len() >> 8) as u8,
                                (response_body.len() & 0xFF) as u8,
                            ];
                            full_response.extend_from_slice(&response_body);
                            if let Err(e) = stream.write_all(&full_response) {
                                error!("Failed to send TCP response: {}", e);
                            }
                        }
                    }
                } else {
                    info!("[TCP] No record found for {}, returning NXDOMAIN", domain);
                    let response_body = DNSHandler::build_nxdomain_response(&buffer[2..query_size + 2]);
                    let mut full_response = vec![
                        (response_body.len() >> 8) as u8,
                        (response_body.len() & 0xFF) as u8,
                    ];
                    full_response.extend_from_slice(&response_body);
                    if let Err(e) = stream.write_all(&full_response) {
                        error!("Failed to send TCP response: {}", e);
                    }
                }
            } else {
                warn!("Failed to extract domain name from TCP request");
            }
        }
        Err(e) => error!("TCP Read error: {}", e),
    }
}

/// Forward a TCP DNS query to the fallback DNS server.
/// Returns the full response (including the 2-byte length prefix) on success.
fn forward_tcp_query(query: &[u8], fallback_dns: &str) -> Option<Vec<u8>> {
    let fallback_addr = if fallback_dns.contains(":") {
        fallback_dns.to_string()
    } else {
        format!("{}:53", fallback_dns)
    };

    let mut stream = TcpStream::connect(&fallback_addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.write_all(query).ok()?;

    // Read the 2-byte length prefix of the DNS response.
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).ok()?;

    let mut full_response = len_buf.to_vec();
    full_response.extend_from_slice(&resp_buf);
    Some(full_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_name() {
        // Example DNS query: header (12 bytes) + question for "example.com"
        // The question section for "example.com" in DNS format:
        // 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, QTYPE, QCLASS
        let mut query = vec![0u8; 12];
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
            0, 1, // QTYPE=A
            0, 1, // QCLASS=IN
        ]);
        let domain = DNSHandler::extract_domain_name(&query).unwrap();
        assert_eq!(domain, "example.com");
    }
}
