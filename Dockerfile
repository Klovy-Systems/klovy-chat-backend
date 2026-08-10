# Stage 1: Kompilacja (Builder)
FROM rust:1-slim as builder

# Instalacja pakietów systemowych wymaganych do kompilacji paczek Rust z podrzędnymi zależnością C (np. OpenSSL)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

# Stage 2: Lekki obraz uruchomieniowy (Debian Slim)
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