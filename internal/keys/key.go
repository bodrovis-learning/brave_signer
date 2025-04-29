package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"brave_signer/internal/utils"
)

// BaseKey holds the shared attributes and methods for key files.
type BaseKey struct {
	Path string
}

func InitEmptyKeyPair(privPath, pubPath string) (*PrivateKey, *PublicKey) {
	return NewPrivateKey(privPath, nil), NewPublicKey(pubPath, nil)
}

func NewPrivateKey(path string, raw ed25519.PrivateKey) *PrivateKey {
	return &PrivateKey{
		BaseKey: BaseKey{Path: path},
		Data:    raw,
	}
}

func NewPublicKey(path string, raw ed25519.PublicKey) *PublicKey {
	return &PublicKey{
		BaseKey: BaseKey{Path: path},
		Data:    raw,
	}
}

func PopulateKeyPair(priv *PrivateKey, pub *PublicKey) error {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key pair: %v", err)
	}

	priv.Data = privKey
	pub.Data = pubKey
	return nil
}

func CheckExistence(priv *PrivateKey, pub *PublicKey) error {
	exists, err := priv.Exists()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("private key already exists at: %s (you can suppress this check by setting --skip-pem-presence-check to true)", priv.Path)
	}

	exists, err = pub.Exists()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("public key already exists at: %s (you can suppress this check by setting --skip-pem-presence-check to true)", pub.Path)
	}

	return nil
}

func (k *BaseKey) Exists() (bool, error) {
	info, err := utils.GetPathInfo(k.Path)
	if err != nil {
		return false, fmt.Errorf("failed to check key path: %v", err)
	}
	return info != nil && !info.IsDir(), nil
}
