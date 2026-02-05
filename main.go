package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"keyway-crypto/crypto"
	"keyway-crypto/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

const version = "1.1.0"

type server struct {
	pb.UnimplementedCryptoServiceServer
	engine *crypto.MultiEngine
}

func (s *server) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	log.Printf("[Encrypt] Received request, plaintext size: %d bytes", len(req.Plaintext))
	ciphertext, iv, authTag, keyVersion, err := s.engine.Encrypt(req.Plaintext)
	if err != nil {
		log.Printf("[Encrypt] Error: %v", err)
		return nil, err
	}
	log.Printf("[Encrypt] Success, ciphertext size: %d bytes, key version: %d", len(ciphertext), keyVersion)
	return &pb.EncryptResponse{
		Ciphertext: ciphertext,
		Iv:         iv,
		AuthTag:    authTag,
		Version:    keyVersion,
	}, nil
}

func (s *server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	keyVersion := req.Version
	// Default to version 1 for backward compatibility with existing data
	if keyVersion == 0 {
		keyVersion = 1
	}
	log.Printf("[Decrypt] Request: ciphertext=%d bytes, iv=%d bytes, authTag=%d bytes, version=%d",
		len(req.Ciphertext), len(req.Iv), len(req.AuthTag), keyVersion)
	log.Printf("[Decrypt] Available versions: %v, has v%d: %v",
		s.engine.AvailableVersions(), keyVersion, s.engine.HasVersion(keyVersion))
	plaintext, err := s.engine.Decrypt(req.Ciphertext, req.Iv, req.AuthTag, keyVersion)
	if err != nil {
		log.Printf("[Decrypt] FAILED for version %d: %v", keyVersion, err)
		return nil, err
	}
	log.Printf("[Decrypt] Success, plaintext size: %d bytes", len(plaintext))
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}

func (s *server) HealthCheck(ctx context.Context, req *pb.Empty) (*pb.HealthResponse, error) {
	log.Printf("[HealthCheck] Received request")
	return &pb.HealthResponse{Healthy: true, Version: version}, nil
}

// loadTLSCredentials loads TLS/mTLS configuration from environment variables.
// Returns nil if TLS is not configured (insecure mode).
//
// Environment variables:
//   - TLS_CERT_FILE: path to server certificate PEM file (required for TLS)
//   - TLS_KEY_FILE: path to server private key PEM file (required for TLS)
//   - TLS_CLIENT_CA_FILE: path to client CA certificate PEM file (enables mTLS)
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile == "" && keyFile == "" {
		return nil, nil // No TLS configured
	}

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("both TLS_CERT_FILE and TLS_KEY_FILE must be set (got cert=%q, key=%q)", certFile, keyFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// If client CA is set, enable mTLS
	clientCAFile := os.Getenv("TLS_CLIENT_CA_FILE")
	if clientCAFile != "" {
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = certPool
	}

	return credentials.NewTLS(tlsConfig), nil
}

// parseEncryptionKeys parses ENCRYPTION_KEYS format: "1:hex_key_1,2:hex_key_2"
// Falls back to ENCRYPTION_KEY (single key as version 1) for backward compatibility
func parseEncryptionKeys() (map[uint32]string, error) {
	keys := make(map[uint32]string)

	// Try new multi-key format first
	multiKeys := os.Getenv("ENCRYPTION_KEYS")
	if multiKeys != "" {
		pairs := strings.Split(multiKeys, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key format: %s (expected version:key)", pair)
			}
			version, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid version number: %s", parts[0])
			}
			if version == 0 {
				return nil, fmt.Errorf("version 0 is reserved, use version >= 1")
			}
			keys[uint32(version)] = strings.TrimSpace(parts[1])
		}
		return keys, nil
	}

	// Fall back to single key format for backward compatibility
	singleKey := os.Getenv("ENCRYPTION_KEY")
	if singleKey != "" {
		keys[1] = singleKey
		return keys, nil
	}

	return nil, fmt.Errorf("ENCRYPTION_KEYS or ENCRYPTION_KEY environment variable is required")
}

func main() {
	keys, err := parseEncryptionKeys()
	if err != nil {
		log.Fatalf("Failed to parse encryption keys: %v", err)
	}

	engine, err := crypto.NewMultiEngine(keys)
	if err != nil {
		log.Fatalf("Failed to initialize crypto engine: %v", err)
	}

	log.Printf("Loaded %d encryption key(s), current version: %d, available versions: %v",
		len(keys), engine.CurrentVersion(), engine.AvailableVersions())

	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	var opts []grpc.ServerOption
	tlsCreds, err := loadTLSCredentials()
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}
	if tlsCreds != nil {
		opts = append(opts, grpc.Creds(tlsCreds))
		if os.Getenv("TLS_CLIENT_CA_FILE") != "" {
			log.Printf("TLS enabled with mTLS (mutual TLS)")
		} else {
			log.Printf("TLS enabled")
		}
	} else {
		log.Printf("WARNING: TLS is disabled, running in insecure mode")
	}

	s := grpc.NewServer(opts...)
	pb.RegisterCryptoServiceServer(s, &server{engine: engine})

	// Health check for k8s/docker
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())

	log.Printf("Crypto service listening on :%s", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
