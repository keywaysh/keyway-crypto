# keyway-crypto

Microservice Go for encrypting/decrypting Keyway secrets using AES-256-GCM.

## Why a separate service?

This microservice isolates the encryption key from the main backend:

- **Security**: The `ENCRYPTION_KEY` never touches the Node.js backend
- **Isolation**: Can be deployed in a private VPC with no internet access
- **Performance**: Go's crypto is faster than Node.js for high-throughput scenarios
- **Auditability**: Smaller codebase, easier to audit

## Architecture

```
┌─────────────────┐       gRPC (mTLS)      ┌─────────────────────┐
│  keyway-backend │ ◄────────────────────► │  keyway-crypto      │
│    (Node.js)    │      :50051            │       (Go)          │
└─────────────────┘                        └─────────────────────┘
                                                   │
                                                   ▼
                                            ENCRYPTION_KEY
                                           (env, never logged)
```

## Encryption Details

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Key size | 256 bits (32 bytes, 64 hex chars) |
| IV | 12 bytes, random per encryption |
| Auth tag | 16 bytes |

Each encryption produces a unique ciphertext even for identical plaintext (random IV).

## Quick Start

### With Docker (recommended)

```bash
# Generate a random key
openssl rand -hex 32

# Run
docker build -t keyway-crypto .
docker run -p 50051:50051 -e ENCRYPTION_KEY=<64-hex-chars> keyway-crypto
```

### Local Development

```bash
# Prerequisites: Go 1.22+, protoc, protoc-gen-go, protoc-gen-go-grpc

# Install protobuf tools
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Build and run
make proto    # Generate gRPC code
make build    # Compile binary
ENCRYPTION_KEY=<64-hex-chars> make run
```

## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `ENCRYPTION_KEY` | AES-256 key in hex (64 chars) | Yes* |
| `ENCRYPTION_KEYS` | Multi-key format `1:hex_key,2:hex_key` | Yes* |
| `GRPC_PORT` | gRPC server port (default: 50051) | No |
| `TLS_CERT_FILE` | Path to server certificate PEM file | No** |
| `TLS_KEY_FILE` | Path to server private key PEM file | No** |
| `TLS_CLIENT_CA_FILE` | Path to client CA certificate PEM file (enables mTLS) | No |

\* Either `ENCRYPTION_KEY` or `ENCRYPTION_KEYS` is required. `ENCRYPTION_KEYS` takes priority.

\** `TLS_CERT_FILE` and `TLS_KEY_FILE` must both be set to enable TLS.

### Generating a secure key

```bash
# macOS/Linux
openssl rand -hex 32

# Output example: a625f804488864fd89a46dbb5abf6962e475dccb8a5674636102b0c3e60dcc1e
```

## TLS / mTLS

The service supports three security modes:

### 1. Insecure (default, development only)

No env vars set — gRPC traffic is unencrypted.

```bash
ENCRYPTION_KEY=<key> ./keyway-crypto
# WARNING: TLS is disabled, running in insecure mode
```

### 2. TLS (server authentication)

Clients verify the server's identity. Set `TLS_CERT_FILE` and `TLS_KEY_FILE`:

```bash
ENCRYPTION_KEY=<key> \
TLS_CERT_FILE=/certs/server.crt \
TLS_KEY_FILE=/certs/server.key \
  ./keyway-crypto
# TLS enabled
```

### 3. mTLS (mutual authentication, recommended for production)

Both server and client authenticate each other. Add `TLS_CLIENT_CA_FILE`:

```bash
ENCRYPTION_KEY=<key> \
TLS_CERT_FILE=/certs/server.crt \
TLS_KEY_FILE=/certs/server.key \
TLS_CLIENT_CA_FILE=/certs/client-ca.crt \
  ./keyway-crypto
# TLS enabled with mTLS (mutual TLS)
```

The client (keyway-backend) must present a certificate signed by the CA in `TLS_CLIENT_CA_FILE`.

### Generating certificates for development

```bash
# Generate CA
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=Keyway Dev CA"

# Generate server certificate
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate client certificate (for mTLS)
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=keyway-backend"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

TLS 1.3 is enforced as minimum version.

## gRPC API

### CryptoService

```protobuf
service CryptoService {
  rpc Encrypt(EncryptRequest) returns (EncryptResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
  rpc HealthCheck(Empty) returns (HealthResponse);
}
```

#### Encrypt

```protobuf
message EncryptRequest {
  string plaintext = 1;  // UTF-8 string to encrypt
}

message EncryptResponse {
  string ciphertext = 1;  // Hex-encoded ciphertext
  string iv = 2;          // Hex-encoded IV (12 bytes)
  string auth_tag = 3;    // Hex-encoded auth tag (16 bytes)
}
```

#### Decrypt

```protobuf
message DecryptRequest {
  string ciphertext = 1;  // Hex-encoded ciphertext
  string iv = 2;          // Hex-encoded IV
  string auth_tag = 3;    // Hex-encoded auth tag
}

message DecryptResponse {
  string plaintext = 1;   // Decrypted UTF-8 string
}
```

## Testing

Comprehensive test suite with 40+ tests covering:

| Category | Tests |
|----------|-------|
| Key validation | Empty, too short, too long, invalid hex |
| Round-trip | Encrypt then decrypt, verify equality |
| Tampering detection | Modified ciphertext, IV, auth tag |
| Edge cases | Empty plaintext, null bytes, unicode |
| Concurrency | 100 goroutines × 100 ops |
| Data sizes | 1 byte to 10 MB |

```bash
# Run all tests
make test

# Verbose output
make test-verbose

# With coverage
go test -cover ./...

# Benchmarks
go test -bench=. ./crypto/
```

## Integration with keyway-backend

The Node.js backend automatically uses this service when `CRYPTO_SERVICE_URL` is set:

```bash
# Without crypto service (local encryption in Node.js)
pnpm run dev

# With crypto service (insecure, development only)
CRYPTO_SERVICE_URL=localhost:50051 pnpm run dev

# With crypto service (mTLS, production)
CRYPTO_SERVICE_URL=localhost:50051 \
CRYPTO_TLS_CERT=/certs/client.crt \
CRYPTO_TLS_KEY=/certs/client.key \
CRYPTO_TLS_CA=/certs/ca.crt \
  pnpm run dev
```

## Security Considerations

1. **Key management**: Never commit `ENCRYPTION_KEY` to version control
2. **Transport**: Use mTLS in production (`TLS_CERT_FILE` + `TLS_KEY_FILE` + `TLS_CLIENT_CA_FILE`)
3. **TLS version**: TLS 1.3 minimum is enforced
4. **Network**: Deploy in a private network for defense in depth
5. **Logging**: The service never logs plaintext or keys
6. **Memory**: Sensitive data is not retained after request completion

## Make Commands

```bash
make proto         # Generate protobuf code
make build         # Build binary
make run           # Run server (requires ENCRYPTION_KEY)
make test          # Run tests
make test-verbose  # Run tests with verbose output
make docker        # Build Docker image
make docker-run    # Run Docker container (requires ENCRYPTION_KEY)
make clean         # Remove build artifacts
```

## License

MIT
