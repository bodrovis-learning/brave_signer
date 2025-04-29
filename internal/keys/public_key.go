package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"brave_signer/internal/logger"
)

// PublicKey holds an Ed25519 public key.
type PublicKey struct {
	BaseKey
	Data ed25519.PublicKey
}

// PEMBlock returns the public key in PEM block form.
func (k *PublicKey) PEMBlock() *pem.Block {
	return &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: k.Data,
	}
}

func (k *PublicKey) SavePEMToFile() error {
	block := k.PEMBlock()

	file, err := os.OpenFile(k.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close public key file")
		}
	}()

	err = pem.Encode(file, block)
	if err != nil {
		return fmt.Errorf("failed to write public key PEM: %v", err)
	}

	return nil
}

func (k *PublicKey) VerifySignature(digest, rawSignature []byte) bool {
	return ed25519.Verify(k.Data, digest, rawSignature)
}

func (k *PublicKey) FingerprintBase64() string {
	hash := sha256.Sum256(k.Data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func LoadPublicFromPEMFile(path string) (*PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("public key file does not contain a valid PEM block")
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("additional data found after the first PEM block, which could indicate multiple PEM blocks or corrupted data")
	}

	if block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("public key file does not contain an Ed25519 public key")
	}

	publicKey := ed25519.PublicKey(block.Bytes)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}

	return &PublicKey{
		Data:    publicKey,
		BaseKey: BaseKey{Path: path},
	}, nil
}
