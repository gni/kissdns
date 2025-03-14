use crate::config::DNSConfig;
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CacheEntry {
    // For TCP, this will be the DNS message (without the 2-byte length header)
    response: Vec<u8>,
    expires_at: Instant,
}

/// Given a DNSConfig and a domain name, resolve the domain using exact match
/// or wildcard matching. Wildcard keys must start with "*." and are matched using ends_with.
fn resolve_domain_from_config(conf: &DNSConfig, domain: &str) -> Option<IpAddr> {
    if let Some(ip_str) = conf.records.get(domain) {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    for (pattern, ip_str) in &conf.records {
        if pattern.starts_with("*.") && domain.ends_with(&pattern[1..]) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// DNSHandler is responsible for handling incoming DNS requests,
/// performing local record lookups (with wildcard support), caching responses,
/// and forwarding queries to a fallback DNS server if needed.
pub struct DNSHandler {
    config: Arc<RwLock<DNSConfig>>,
    cache: Arc<RwLock<HashMap<(String, u16), CacheEntry>>>,
    shutdown: Arc<AtomicBool>,
}

impl DNSHandler {
    /// Create a new DNSHandler with the provided configuration and shutdown flag.
    pub fn new(config: DNSConfig, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            cache: Arc::new(RwLock::new(HashMap::new())),
            shutdown,
        }
    }

    /// Parse the DNS query and return a tuple (domain, QTYPE).
    /// Returns None if the query is malformed.
    fn parse_query(request: &[u8]) -> Option<(String, u16)> {
        let domain = Self::extract_domain_name(request)?;
        // After the domain name comes a null byte then QTYPE (2 bytes) and QCLASS (2 bytes).
        let mut pos = 12;
        while pos < request.len() && request[pos] != 0 {
            pos += request[pos] as usize + 1;
        }
        pos += 1; // Skip the null byte.
        if pos + 4 > request.len() {
            return None;
        }
        let qtype = ((request[pos] as u16) << 8) | (request[pos + 1] as u16);
        Some((domain, qtype))
    }

    /// For convenience, this method wraps the free function for wildcard resolution.
    fn resolve_domain(&self, domain: &str) -> Option<IpAddr> {
        let conf = self.config.read().expect("Failed to acquire config read lock");
        resolve_domain_from_config(&conf, domain)
    }

    /// Start both UDP and TCP DNS servers on the given port.
    /// The UDP server loop and the TCP listener run concurrently.
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

        // Spawn the TCP server in a separate thread.
        let config_clone = Arc::clone(&self.config);
        let cache_clone = Arc::clone(&self.cache);
        let shutdown_clone = Arc::clone(&self.shutdown);
        std::thread::spawn(move || {
            let tcp_listener = match TcpListener::bind(&tcp_address) {
                Ok(listener) => listener,
                Err(e) => {
                    error!("Failed to bind TCP socket on {}: {}", tcp_address, e);
                    return;
                }
            };
            info!("TCP DNS Server running on {}", tcp_address);
            tcp_listener
                .set_nonblocking(true)
                .expect("Failed to set non-blocking mode");
            loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    info!("Shutting down TCP server");
                    break;
                }
                match tcp_listener.accept() {
                    Ok((mut stream, addr)) => {
                        info!("Accepted TCP connection from {}", addr);
                        let config = Arc::clone(&config_clone);
                        let cache = Arc::clone(&cache_clone);
                        std::thread::spawn(move || {
                            handle_tcp_request(&mut stream, &config, &cache);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        error!("Error accepting TCP connection: {}", e);
                    }
                }
            }
        });

        udp_socket
            .set_nonblocking(true)
            .expect("Failed to set UDP socket to non-blocking");
        let mut buf = [0u8; 512];
        while !self.shutdown.load(Ordering::SeqCst) {
            match udp_socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    if size < 12 {
                        warn!("Received malformed DNS request (too small) from {}", src);
                        continue;
                    }
                    if let Some((domain, qtype)) = Self::parse_query(&buf[..size]) {
                        let cache_key = (domain.clone(), qtype);
                        if let Some(entry) = self.cache.read().unwrap().get(&cache_key) {
                            if Instant::now() < entry.expires_at {
                                info!("Cache hit for {} (qtype {})", domain, qtype);
                                // Clone the cached response and update its transaction ID using buf[0..2].
                                let mut cached_response = entry.response.clone();
                                cached_response[0] = buf[0];
                                cached_response[1] = buf[1];
                                if let Err(e) = udp_socket.send_to(&cached_response, &src) {
                                    error!("Failed to send cached response to {}: {}", src, e);
                                }
                                continue;
                            }
                        }
                        let response = if let Some(ip) = self.resolve_domain(&domain) {
                            match (qtype, ip) {
                                (1, IpAddr::V4(ipv4)) | (255, IpAddr::V4(ipv4)) => {
                                    info!("[UDP] Resolving {} -> {}", domain, ipv4);
                                    DNSHandler::build_dns_response(&buf[..size], IpAddr::V4(ipv4), qtype)
                                }
                                (28, IpAddr::V6(ipv6)) | (255, IpAddr::V6(ipv6)) => {
                                    info!("[UDP] Resolving {} -> {}", domain, ipv6);
                                    DNSHandler::build_dns_response(&buf[..size], IpAddr::V6(ipv6), qtype)
                                }
                                _ => {
                                    info!("[UDP] Record type mismatch for {}, returning NXDOMAIN", domain);
                                    DNSHandler::build_nxdomain_response(&buf[..size])
                                }
                            }
                        } else {
                            let conf = self.config.read().expect("Failed to read config");
                            if !conf.fallback_dns.is_empty() {
                                match Self::forward_udp_query(&buf[..size], &conf.fallback_dns) {
                                    Some(mut resp) => {
                                        info!("[UDP] Fallback resolution for {} succeeded", domain);
                                        // Update the fallback response's transaction ID using buf[0..2]
                                        if resp.len() >= 2 {
                                            resp[0] = buf[0];
                                            resp[1] = buf[1];
                                        }
                                        resp
                                    }
                                    None => {
                                        info!("[UDP] Fallback resolution for {} failed, returning NXDOMAIN", domain);
                                        DNSHandler::build_nxdomain_response(&buf[..size])
                                    }
                                }
                            } else {
                                info!("[UDP] No record found for {}, returning NXDOMAIN", domain);
                                DNSHandler::build_nxdomain_response(&buf[..size])
                            }
                        };
                        // Cache the response for 60 seconds.
                        let expires = Instant::now() + Duration::from_secs(60);
                        self.cache.write().unwrap().insert(cache_key, CacheEntry { response: response.clone(), expires_at: expires });
                        if let Err(e) = udp_socket.send_to(&response, &src) {
                            error!("Failed to send DNS response to {}: {}", src, e);
                        }
                    } else {
                        warn!("Failed to parse DNS query from {}", src);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(e) => error!("Error receiving UDP request: {}", e),
            }
        }
        info!("Shutting down UDP server");
    }

    /// Forward a UDP DNS query to the fallback DNS server.
    fn forward_udp_query(query: &[u8], fallback_dns: &str) -> Option<Vec<u8>> {
        let fallback_addr = if fallback_dns.contains(":") {
            fallback_dns.to_string()
        } else {
            format!("{}:53", fallback_dns)
        };
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        sock.send_to(query, &fallback_addr).ok()?;
        let mut buf = [0u8; 512];
        let (size, _) = sock.recv_from(&mut buf).ok()?;
        Some(buf[..size].to_vec())
    }

    /// Extract the queried domain name from a DNS request packet.
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

    /// Build a DNS response packet with an answer pointing to the given IP address.
    /// This function handles both A (qtype=1) and AAAA (qtype=28) responses.
    fn build_dns_response(request: &[u8], ip: IpAddr, qtype: u16) -> Vec<u8> {
        let mut response = Vec::new();
        // Transaction ID.
        response.extend_from_slice(&request[..2]);
        // Flags: Response, No Error.
        response.extend_from_slice(&[0x81, 0x80]);
        // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        // Copy the question section.
        let mut question_end = 12;
        while question_end < request.len() && request[question_end] != 0 {
            question_end += request[question_end] as usize + 1;
        }
        question_end += 5; // Skip the null byte and QTYPE/QCLASS.
        response.extend_from_slice(&request[12..question_end]);
        // Answer: pointer to domain name at offset 0x0c.
        response.extend_from_slice(&[0xc0, 0x0c]);
        match (qtype, ip) {
            (1, IpAddr::V4(ipv4)) | (255, IpAddr::V4(ipv4)) => {
                // Type A, Class IN.
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                // TTL: 60 seconds.
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
                // Data length: 4 bytes.
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&ipv4.octets());
            }
            (28, IpAddr::V6(ipv6)) | (255, IpAddr::V6(ipv6)) => {
                // Type AAAA, Class IN.
                response.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]);
                // TTL: 60 seconds.
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
                // Data length: 16 bytes.
                response.extend_from_slice(&[0x00, 0x10]);
                response.extend_from_slice(&ipv6.octets());
            }
            _ => {
                // If record type does not match, return NXDOMAIN.
                return Self::build_nxdomain_response(request);
            }
        }
        response
    }

    /// Build a DNS response packet indicating NXDOMAIN (non-existent domain).
    fn build_nxdomain_response(request: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&request[..2]); // Transaction ID.
        response.extend_from_slice(&[0x81, 0x83]); // Flags: response, NXDOMAIN.
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut question_end = 12;
        while question_end < request.len() && request[question_end] != 0 {
            question_end += request[question_end] as usize + 1;
        }
        question_end += 5;
        if question_end <= request.len() {
            response.extend_from_slice(&request[12..question_end]);
        }
        response
    }
}

/// Handle a single TCP DNS request.
/// This function uses the same parsing and resolution logic as UDP,
/// but it first reads the 2-byte length prefix from the TCP stream.
fn handle_tcp_request(
    stream: &mut TcpStream,
    config: &Arc<RwLock<DNSConfig>>,
    cache: &Arc<RwLock<HashMap<(String, u16), CacheEntry>>>,
) {
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
            let query = &buffer[0..query_size + 2];
            if let Some((domain, qtype)) = DNSHandler::parse_query(&buffer[2..query_size + 2]) {
                let cache_key = (domain.clone(), qtype);
                if let Some(entry) = cache.read().unwrap().get(&cache_key) {
                    if Instant::now() < entry.expires_at {
                        info!("Cache hit for {} (qtype {})", domain, qtype);
                        let mut cached_body = entry.response.clone();
                        // For TCP, the cached DNS message starts at offset 0.
                        cached_body[0] = buffer[2];
                        cached_body[1] = buffer[3];
                        let mut full_response = vec![
                            (cached_body.len() >> 8) as u8,
                            (cached_body.len() & 0xFF) as u8,
                        ];
                        full_response.extend_from_slice(&cached_body);
                        if let Err(e) = stream.write_all(&full_response) {
                            error!("Failed to send cached TCP response: {}", e);
                        }
                        return;
                    }
                }
                let conf = config.read().expect("Failed to acquire config lock");
                let response_body = if let Some(ip) = resolve_domain_from_config(&conf, &domain) {
                    match (qtype, ip) {
                        (1, IpAddr::V4(ipv4)) | (255, IpAddr::V4(ipv4)) => {
                            info!("[TCP] Resolving {} -> {}", domain, ipv4);
                            DNSHandler::build_dns_response(&buffer[2..query_size + 2], IpAddr::V4(ipv4), qtype)
                        }
                        (28, IpAddr::V6(ipv6)) | (255, IpAddr::V6(ipv6)) => {
                            info!("[TCP] Resolving {} -> {}", domain, ipv6);
                            DNSHandler::build_dns_response(&buffer[2..query_size + 2], IpAddr::V6(ipv6), qtype)
                        }
                        _ => {
                            info!("[TCP] Record type mismatch for {}, returning NXDOMAIN", domain);
                            DNSHandler::build_nxdomain_response(&buffer[2..query_size + 2])
                        }
                    }
                } else if !conf.fallback_dns.is_empty() {
                    match forward_tcp_query(query, &conf.fallback_dns) {
                        Some(mut resp) => {
                            info!("[TCP] Fallback resolution for {} succeeded", domain);
                            // Now resp is the DNS message (without the 2-byte length header).
                            if resp.len() >= 2 {
                                resp[0] = buffer[2];
                                resp[1] = buffer[3];
                            }
                            resp
                        }
                        None => {
                            info!("[TCP] Fallback resolution for {} failed, returning NXDOMAIN", domain);
                            DNSHandler::build_nxdomain_response(&buffer[2..query_size + 2])
                        }
                    }
                } else {
                    info!("[TCP] No record found for {}, returning NXDOMAIN", domain);
                    DNSHandler::build_nxdomain_response(&buffer[2..query_size + 2])
                };
                let expires = Instant::now() + Duration::from_secs(60);
                cache.write().unwrap().insert(cache_key, CacheEntry { response: response_body.clone(), expires_at: expires });
                let mut full_response = vec![
                    (response_body.len() >> 8) as u8,
                    (response_body.len() & 0xFF) as u8,
                ];
                full_response.extend_from_slice(&response_body);
                if let Err(e) = stream.write_all(&full_response) {
                    error!("Failed to send TCP response: {}", e);
                }
            } else {
                warn!("Failed to parse DNS query from TCP request");
            }
        }
        Err(e) => error!("TCP Read error: {}", e),
    }
}

/// Forward a TCP DNS query to the fallback DNS server.
/// Returns the DNS message (without the 2-byte length header) on success.
fn forward_tcp_query(query: &[u8], fallback_dns: &str) -> Option<Vec<u8>> {
    let fallback_addr = if fallback_dns.contains(":") {
        fallback_dns.to_string()
    } else {
        format!("{}:53", fallback_dns)
    };
    let mut stream = TcpStream::connect(&fallback_addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.write_all(query).ok()?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).ok()?;
    // Return only the DNS message (without the 2-byte length header)
    Some(resp_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_name() {
        // Create a query for "example.com"
        let mut query = vec![0u8; 12];
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
            0, 1, // QTYPE=A.
            0, 1, // QCLASS=IN.
        ]);
        let domain = DNSHandler::extract_domain_name(&query).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_parse_query() {
        let mut query = vec![0u8; 12];
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
            0, 1,
            0, 1,
        ]);
        let (domain, qtype) = DNSHandler::parse_query(&query).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
    }
}
