# Stage 1: Budowanie binarne w środowisku Rust
FROM rust:1.80-slim as builder

WORKDIR /usr/src/app

# Kopiowanie zależności i kodu źródłowego
COPY . .

# Kompilacja wersji produkcyjnej
RUN cargo build --release

# Stage 2: Lekka obraz produkcyjny (Debian Slim)
FROM debian:bookworm-slim

# Instalacja podstawowych bibliotek systemowych (np. CA certificates dla HTTPS)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopiowanie zebranych binarów z pierwszego etapu
COPY --from=builder /usr/src/app/target/release/klovy-chat-server /app/klovy-chat-server
COPY --from=builder /usr/src/app/target/release/migrate-message-content-seal /app/migrate-message-content-seal

# Domyślny port aplikacji (dostosuj jeśli jest inny)
EXPOSE 6701

CMD ["/app/klovy-chat-server"]