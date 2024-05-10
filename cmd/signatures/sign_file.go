package signatures

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/utils"

	"github.com/spf13/cobra"
)

func init() {
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	signaturesSignFileCmd.Flags().String("priv-key", "priv_key.pem", "Path to your private key")
	signaturesSignFileCmd.Flags().String("file", "", "Path to the file that should be signed")
	err := signaturesSignFileCmd.MarkFlagRequired("file")
	utils.HaltOnErr(err)

	signaturesSignFileCmd.Flags().String("signer-id", "", "Signer's name or identifier")
	err = signaturesSignFileCmd.MarkFlagRequired("signer-id")
	utils.HaltOnErr(err)
}

var signaturesSignFileCmd = &cobra.Command{
	Use:   "signfile",
	Short: "Sign the file.",
	Long:  `Sign the specified file using an RSA private key and store the signature inside a .sig file named after the original file. You'll be asked for a passphrase to decrypt the private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		privPath, err := cmd.Flags().GetString("priv-key")
		utils.HaltOnErr(err)
		filePath, err := cmd.Flags().GetString("file")
		utils.HaltOnErr(err)
		signerId, err := cmd.Flags().GetString("signer-id")
		utils.HaltOnErr(err)

		const (
			minSignerInfoLength = 1
			maxSignerInfoLength = 65535
		)

		if len(signerId) < minSignerInfoLength || len(signerId) > maxSignerInfoLength {
			utils.HaltOnErr(
				fmt.Errorf("signer information should be between %d and %d characters", minSignerInfoLength, maxSignerInfoLength),
			)
		}

		fullFilePath, err := utils.ProcessFilePath(filePath)
		utils.HaltOnErr(err)

		fullPrivKeyPath, err := utils.ProcessFilePath(privPath)
		utils.HaltOnErr(err)

		privateKey, err := loadPrivateKey(fullPrivKeyPath)
		utils.HaltOnErr(err)

		digest, err := hashFile(fullFilePath)
		utils.HaltOnErr(err)

		signature, err := signDigest(digest, privateKey)
		utils.HaltOnErr(err)

		signaturePackage, err := makeSignaturePackage(signature, signerId)
		utils.HaltOnErr(err)

		err = writeSignatureToFile(signaturePackage, fullFilePath)
		utils.HaltOnErr(err)
	},
}

func makeSignaturePackage(signature []byte, signerInfo string) ([]byte, error) {
	// Prepare a buffer to hold the binary data
	var buf bytes.Buffer

	// Write the length of the signer info as a uint32
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfo))); err != nil {
		return nil, err
	}

	// Write the signer info string
	if _, err := buf.WriteString(signerInfo); err != nil {
		return nil, err
	}

	// Write the signature
	if _, err := buf.Write(signature); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writeSignatureToFile(signaturePackage []byte, initialFilePath string) error {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)
	extension := filepath.Ext(baseName)
	nameWithoutExt := baseName[:len(baseName)-len(extension)]

	sigFilePath := filepath.Join(dir, nameWithoutExt+".sig")

	return os.WriteFile(sigFilePath, signaturePackage, 0o644)
}

func signDigest(digest []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA3_256, digest, opts)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func decodePEMFile(pkPath string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, err
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
		return nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	return nonce, salt, nil
}

func loadPrivateKey(pkPath string) (*rsa.PrivateKey, error) {
	block, err := decodePEMFile(pkPath)
	if err != nil {
		return nil, err
	}

	nonce, salt, err := getSaltAndNonce(block)
	if err != nil {
		return nil, err
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, err
	}

	// Derive the key from the passphrase and salt
	key := utils.DeriveKey(passphrase, []byte(salt))

	crypter, err := utils.MakeCrypter(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the private key
	plaintext, err := crypter.Open(nil, []byte(nonce), block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("private key file descryption failed: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
