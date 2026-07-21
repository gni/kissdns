# KissDNS

**Keep It Simple, Stupid DNS** for Developers

KissDNS is a lightweight DNS server built in Rust, designed for developers who don't have root rights
or need to work in secure environments where traditional DNS configuration isn't available. 
Its focus is on simplicity and ease of use, allowing you to quickly spin up a local DNS server 
for development, testing, and secure domain resolution without requiring administrative privileges.

## Features

- **No Root Required:**  
  Run KissDNS as a non-privileged user, ideal for secure environments or restricted development setups.

- **Simple & Minimalistic:**  
  Keep it simple, stupid (KISS) – no extra frills, just a straightforward DNS server.

- **Wildcard Resolution:**  
  Supports wildcard domains (e.g., `*.test.demo`) so you can resolve multiple subdomains with a single record.

- **Caching:**  
  Caches DNS responses for 60 seconds to reduce latency on repeated queries.

- **Fallback DNS:**  
  If a domain is not found in your local configuration, queries are forwarded 
  to a fallback DNS server (e.g., Google’s 8.8.8.8).

- **Dual Protocol Support:**  
  Handles both UDP and TCP DNS queries.

- **Graceful Shutdown:**  
  Uses a shutdown flag and Ctrl+C handler for clean termination.

## Installation

Simply install KissDNS via Cargo:

```sh
cargo install kissdns
```

## Running the DNS Server

KissDNS uses a JSON configuration file (by default, `hosts.json`). On the first run, 
if the configuration file is not found in the binary’s directory, 
a default configuration file will be created automatically.

You can run the server with default settings:

```sh
kissdns
```

Or pass a custom configuration file path and/or port as command-line arguments:

- **Custom Port Only (e.g., 5532):**

  ```sh
  kissdns 5532
  ```

- **Custom Configuration File Only (e.g., `myconfig.json`):**

  ```sh
  kissdns myconfig.json
  ```

- **Both Custom Configuration File and Port:**

  ```sh
  kissdns myconfig.json 5532
  ```

## Example `hosts.json`

If no configuration file is found, KissDNS creates a default file. For example:

```json
{
  "records": {
    "dev.demo": "127.0.0.1",
    "api.demo": "127.0.0.1",
    "*.test.demo": "10.0.0.5",
    "ipv6.demo": "fe80::6049:67ff:fedb:e84d"
  },
  "fallback_dns": "8.8.8.8"
}
```

- **records:**  
  Maps domain names (including wildcards) to IP addresses.
  
- **fallback_dns:**  
  DNS server used for queries not found in your local configuration.

See [schema definition](docs/schema.v1.json) for more details.

## Running in OCI container

1\. Retrieve container

Pull published container from ghcr.io:

```sh
docker pull ghcr.io/unsektor/kissdns:latest-alpine

# ... or with podman:
podman pull ghcr.io/unsektor/kissdns:latest-alpine
```

or build manually:

```sh
docker build --target kissdns-alpine -t kissdns-alpine .

# ... or with podman:
podman build --target kissdns-alpine -t kissdns-alpine .
```

> [!NOTE]
> Typically, building `kissdns-alpine` image is required only once.
> This image will contain only the built `kissdns` binary,
> without build tools and source code.
> Compilation process itself occurs inside the `kissdns-builder-alpine` container.
> Such design is used to get optimal image.

> [!TIP]
> When it's required to play with compilation interactively, such command may be used:
>
> ```sh
> docker build --target kissdns-builder-alpine -t kissdns-builder-alpine .
> docker run -it --rm --volume "$PWD:/src" --entrypoint '/bin/bash' kissdns-builder-alpine
> # ... do something inside the container, for example `cargo test`
> ```

2\. Run binary from container

Synopsis:

```
docker run --rm -it kissdns-alpine [kissdns ARGUMENTS ...]
```

> [!NOTE]
> Container filesystem is isolated from host filesystem, to make host directories accessible from the container,
> it's required to mount it on `docker run` command invocation, for example:
>
> ```sh
> cat << 'EOF' > /tmp/kissdns-config.json
> {
>   "records": {
>     "dev.demo": "172.0.0.1",
>     "api.demo": "127.0.0.1",
>     "*.test.demo": "10.0.0.5",
>     "ipv6.demo": "fe80::6049:67ff:fedb:e84d"
>   },
>   "fallback_dns": "8.8.8.8"
> }
> EOF
> 
> docker run --rm \
>   --publish '5533:5533/tcp' \
>   --publish '5533:5533/udp' \
>   --volume "/tmp/kissdns-config.json:/etc/kissdns-config.json:ro" \
>   kissdns-alpine -- /etc/kissdns-config.json
> ```
> or with additional verbosity:
> ```sh
> docker run --rm \
>   --publish '5533:5533/tcp' \
>   --publish '5533:5533/udp' \
>   --env 'RUST_LOG=debug' \
>   --volume "/tmp/kissdns-config.json:/etc/kissdns-config.json:ro" \
>   kissdns-alpine -- /etc/kissdns-config.json
> ```

> [!TIP]
> Like in example from previous step, when it's required to play with container (containing
> the only `kissdns`) interactively, such command may be used:
>
> ```sh
> docker run -it --rm --volume "$PWD:/opt/data" --entrypoint '/bin/bash' kissdns-alpine
> # ... do something inside the container, for example `kissdns 2342`
> ```

## Debugging

KissDNS uses the `env_logger` crate for logging. To run with INFO-level logs:

```sh
RUST_LOG=info kissdns
```

Or with DEBUG-level logs:

```sh
RUST_LOG=debug kissdns
```

These commands will display additional log messages for easier debugging.

## Test with dig and nslookup

dig

```
$ dig @127.0.0.1 -p 5533 api.demo

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16792
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;api.demo.                  IN      A

;; ANSWER SECTION:
api.demo.           60      IN      A       127.0.0.1

;; Query time: 0 msec
;; SERVER: 127.0.0.1#5533(127.0.0.1) (UDP)
;; WHEN: Fri Mar 14 01:34:28 CET 2025
;; MSG SIZE  rcvd: 46
```

nslookup

```
$ nslookup -port=5533 ipv6.kiss.dns 127.0.0.1

Server:         127.0.0.1
Address:        127.0.0.1#5533

Non-authoritative answer:
Name:   ipv6.kiss.dns
Address: fe80::6049:67ff:fedb:e84d

Authoritative answers can be found from:
```

## Why KissDNS?

KissDNS stands for **Keep It Simple, Stupid DNS**. It’s designed for developers working in environments 
without root privileges or under strict security restrictions. KissDNS offers a quick, simple, 
and flexible solution for local domain resolution without complex system modifications.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
