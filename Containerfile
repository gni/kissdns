FROM rust:alpine AS kissdns-builder-alpine

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Empty source to cache dependencies
RUN set -aeux ; mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --locked && sync && \
    rm -rf src && sync

COPY src ./src
RUN cargo build --release --locked

FROM alpine:latest AS kissdns-alpine

COPY --from=kissdns-builder-alpine /app/target/release/kissdns /usr/local/bin/
RUN adduser -D -u 1000 kissdns && \
    chown kissdns:kissdns /usr/local/bin/kissdns

USER kissdns
WORKDIR /home/kissdns

ENTRYPOINT ["/usr/local/bin/kissdns"]
CMD ["5533"]
EXPOSE 5533/tcp 5533/udp

HEALTHCHECK --interval=5s --timeout=5s --retries=10 CMD nc -zv 127.0.0.1 5533 || exit 1
