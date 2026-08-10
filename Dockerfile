# Stage 1: Kompilacja na bazie Debiana Bookworm (zapewnia zgodność GLIBC z obrazem wykonawczym)
FROM rust:1-slim-bookworm as builder

# Instalacja narzędzi build-essential dla pakietów C oraz nagłówków OpenSSL
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Kopiowanie kodu źródłowego
COPY . .

# Kompilacja w trybie produkcyjnym
RUN cargo build --release

# Stage 2: Lekki obraz uruchomieniowy (Debian Bookworm Slim)
FROM debian:bookworm-slim

# Instalacja certyfikatów CA oraz OpenSSL do komunikacji HTTPS/TLS w runtime
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopiowanie skompilowanych plików binarnych ze etapu builder
COPY --from=builder /usr/src/app/target/release/klovy-chat-server /app/klovy-chat-server
COPY --from=builder /usr/src/app/target/release/migrate-message-content-seal /app/migrate-message-content-seal

EXPOSE 6701

CMD ["/app/klovy-chat-server"]