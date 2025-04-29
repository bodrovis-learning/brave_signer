package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"brave_signer/internal/logger"
)

// PrivateKey holds an Ed25519 private key and PEM-related metadata.
type PrivateKey struct {
	BaseKey
	Data    ed25519.PrivateKey
	PEMData *pem.Block
}

// SealWithPassphrase applies Argon2 + AES encryption to the private key.
func (k *PrivateKey) SealWithPassphrase(cryptoConfig KeyEncryptionConfig) error {
	salt, err := generateSalt(cryptoConfig.SaltSize)
	if err != nil {
		return err
	}

	derivedKey, err := DeriveKey(cryptoConfig, salt)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %v", err)
	}

	crypter, err := generateCrypter(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create crypter: %v", err)
	}

	nonce, err := generateNonce(crypter)
	if err != nil {
		return fmt.Errorf("failed to make nonce: %v", err)
	}

	encrypted := crypter.Seal(nil, nonce, k.Data, nil)

	zeroize(k.Data)
	k.Data = nil

	k.PEMData = &pem.Block{
		Type:  "ENCRYPTED ED25519 PRIVATE KEY",
		Bytes: encrypted,
		Headers: map[string]string{
			"Nonce":                   base64.StdEncoding.EncodeToString(nonce),
			"Salt":                    base64.StdEncoding.EncodeToString(salt),
			"Key-Derivation-Function": "Argon2",
		},
	}

	return nil
}

func (k *PrivateKey) SavePEMToFile() error {
	if k.PEMData == nil {
		return fmt.Errorf("cannot save private key: no PEM data present (did you forget to seal the key?)")
	}

	file, err := os.OpenFile(k.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close private key file")
		}
	}()

	if err := pem.Encode(file, k.PEMData); err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %v", err)
	}

	return nil
}

func (k *PrivateKey) SignMessage(message []byte) []byte {
	signature := ed25519.Sign(k.Data, message)
	return signature
}

func LoadPrivateFromPEMFile(path string, cryptoConfig KeyEncryptionConfig) (*PrivateKey, error) {
	block, err := decodePEMFile(path)
	if err != nil {
		return nil, err
	}

	nonce, salt, err := getSaltAndNonce(block)
	if err != nil {
		return nil, err
	}

	key, err := DeriveKey(cryptoConfig, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := generateCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to make crypter: %v", err)
	}

	// Decrypt the private key
	plaintext, err := crypter.Open(nil, nonce, block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("private key file decryption failed: %v", err)
	}

	// Parse the Ed25519 private key
	privateKey := ed25519.PrivateKey(plaintext)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return &PrivateKey{
		BaseKey: BaseKey{Path: path},
		Data:    privateKey,
		PEMData: block,
	}, nil
}

func getSaltAndNonce(block *pem.Block) ([]byte, []byte, error) {
	nonceB64, ok := block.Headers["Nonce"]
	if !ok {
		return nil, nil, fmt.Errorf("nonce not found in PEM headers")
	}
	saltB64, ok := block.Headers["Salt"]
	if !ok {
		return nil, nil, fmt.Errorf("salt not found in PEM headers")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %v", err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	return nonce, salt, nil
}

func decodePEMFile(path string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %v", err)
	}

	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM file: extra data encountered after PEM block")
	}

	return block, nil
}

func generateSalt(saltSize int) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	return salt, nil
}

func generateNonce(crypter cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, crypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	return nonce, nil
}

func generateCrypter(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	return gcm, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
