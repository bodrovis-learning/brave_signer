package hashers

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"

	"brave_signer/internal/logger"
	"golang.org/x/crypto/sha3"
)

type Hasher struct {
	Name     string
	HashType crypto.Hash
	Hasher   hash.Hash
}

var (
	DefaultHasherName   = "sha3-256"
	DefaultHashFunction = hashFunctionMap[DefaultHasherName]
)

var hashFunctionMap = map[string]struct {
	Constructor func() hash.Hash
	Hash        crypto.Hash
}{
	"sha3-256": {sha3.New256, crypto.SHA3_256},
	"sha3-512": {sha3.New512, crypto.SHA3_512},
	"sha256":   {sha256.New, crypto.SHA256},
	"sha512":   {sha512.New, crypto.SHA512},
}

func New(algo string) *Hasher {
	if hf, ok := hashFunctionMap[algo]; ok {
		return &Hasher{
			Name:     algo,
			HashType: hf.Hash,
			Hasher:   hf.Constructor(),
		}
	}

	logger.Warn(fmt.Errorf("unsupported hash algorithm"), "requested:", algo, "fallback to default:", DefaultHasherName)

	return &Hasher{
		Name:     DefaultHasherName,
		HashType: DefaultHashFunction.Hash,
		Hasher:   DefaultHashFunction.Constructor(),
	}
}

func (h *Hasher) HashFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", filePath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close file after hashing")
		}
	}()

	// Important: reset hasher before each new hashing, in case the Hasher instance is reused
	h.Hasher.Reset()

	if _, err := io.Copy(h.Hasher, file); err != nil {
		return nil, fmt.Errorf("error while hashing file %s: %w", filePath, err)
	}

	return h.Hasher.Sum(nil), nil
}
