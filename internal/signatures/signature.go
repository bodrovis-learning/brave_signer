package signatures

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/internal/keys"
)

type Signature struct {
	Data    []byte
	Package []byte
}

func New(data []byte) (*Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("signature data is empty")
	}
	return &Signature{
		Data:    data,
		Package: nil,
	}, nil
}

func (s *Signature) GeneratePackage(signerInfo string) (*Signature, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfo))); err != nil {
		return nil, fmt.Errorf("failed to write signer info length: %v", err)
	}

	if _, err := buf.WriteString(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to write signer info: %v", err)
	}

	if _, err := buf.Write(s.Data); err != nil {
		return nil, fmt.Errorf("failed to write signature: %v", err)
	}

	s.Package = buf.Bytes()
	return s, nil
}

func (s *Signature) SaveToSIGFile(initialFilePath string) (string, error) {
	sigFilePath := filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")

	if err := os.WriteFile(sigFilePath, s.Package, 0o644); err != nil {
		return "", err
	}

	return sigFilePath, nil
}

func (s *Signature) VerifyDigest(digest []byte, publicKey *keys.PublicKey) ([]byte, error) {
	buf := bytes.NewReader(s.Data)

	var nameLength uint32
	if err := binary.Read(buf, binary.BigEndian, &nameLength); err != nil {
		return nil, fmt.Errorf("failed to read signer info length: %v", err)
	}

	// Read the signer info
	signerInfo := make([]byte, nameLength)
	if _, err := buf.Read(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to read signer info: %v", err)
	}

	// The rest of the buffer is the signature
	signatureBytes := make([]byte, buf.Len())
	if _, err := buf.Read(signatureBytes); err != nil {
		return nil, fmt.Errorf("failed to read signature: %v", err)
	}

	if !publicKey.VerifySignature(digest, signatureBytes) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return signerInfo, nil
}

func LoadRawFromSIGFile(initialFilePath string) (*Signature, error) {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)

	sigFilePath := filepath.Join(dir, baseName+".sig")

	data, err := os.ReadFile(sigFilePath)
	if err != nil {
		return nil, err
	}

	return &Signature{
		Data:    data,
		Package: nil,
	}, nil
}
