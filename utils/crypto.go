package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

// MakeNonce creates a nonce suitable for use with the provided AEAD cipher.
func MakeNonce(crypter cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, crypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

// MakeCrypter creates a cipher.AEAD from a given key using AES in GCM mode.
func MakeCrypter(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// DeriveKey generates a cryptographic key using Argon2 from a given passphrase and salt.
func DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)
}

// MakeSalt generates a 16-byte cryptographic salt.
func MakeSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}
