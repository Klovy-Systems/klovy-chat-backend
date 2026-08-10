FROM rust:1.94-slim as builder

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/klovy-chat-server /app/klovy-chat-server
COPY --from=builder /usr/src/app/target/release/migrate-message-content-seal /app/migrate-message-content-seal

EXPOSE 6701

CMD ["/app/klovy-chat-server"]