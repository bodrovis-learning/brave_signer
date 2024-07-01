package signatures

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/logger"
	"brave_signer/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	signaturesCmd.AddCommand(signaturesVerifyFileCmd)

	signaturesVerifyFileCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to the Ed25519 public key in PEM format")
}

var signaturesVerifyFileCmd = &cobra.Command{
	Use:   "verifyfile",
	Short: "Verify the signature of a file.",
	Long: `Verify the digital signature of a specified file using an Ed25519 public key. The command expects a signature file named "<original_filename>.sig" located in the same directory as the file being verified. The public key should be in PEM format.

The process involves:
1. Loading the Ed25519 public key.
2. Reading the signature from the .sig file.
3. Hashing the file using the specified hash algorithm.
4. Verifying the signature against the hash of the file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting signature verification process...")

		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		logger.Info("Loading public key...")

		fullPubKeyPath, err := utils.ProcessFilePath(localViper.GetString("pub-key-path"))
		logger.HaltOnErr(err, "failed to process pub key path")

		publicKey, err := loadPublicKey(fullPubKeyPath)
		logger.HaltOnErr(err, "cannot load pub key from file")

		logger.Info("Loading file to verify and signature...")

		fullFilePath, err := utils.ProcessFilePath(localViper.GetString("file-path"))
		logger.HaltOnErr(err, "failed to process file path")

		signatureRaw, err := readSignature(fullFilePath)
		logger.HaltOnErr(err, "cannot read signature")

		logger.Info("Hashing the file...")

		hashAlgo := localViper.GetString("hash-algo")
		hasher, hashType := getHashFunction(hashAlgo)

		digest, err := hashFile(fullFilePath, hasher)
		logger.HaltOnErr(err, "cannot hash file")

		logger.Info("Verifying signature...")

		signerInfo, err := verifyFileSignature(publicKey, digest, signatureRaw)
		logger.HaltOnErr(err, "cannot verify signature")

		logger.Info(fmt.Sprintf("Verification successful for file: %s\n", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf("Verified using public key: %s\n", filepath.Base(fullPubKeyPath)))
		logger.Info(fmt.Sprintf("Hash Algorithm: %s\n", hashType.String()))
		logger.Info(fmt.Sprintf("Signer info:\n%s\n", signerInfo))
	},
}

func verifyFileSignature(publicKey ed25519.PublicKey, digest []byte, signatureRaw []byte) ([]byte, error) {
	buf := bytes.NewReader(signatureRaw)

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
	signature := make([]byte, buf.Len())
	if _, err := buf.Read(signature); err != nil {
		return nil, fmt.Errorf("failed to read signature: %v", err)
	}

	if !ed25519.Verify(publicKey, digest, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return signerInfo, nil
}

func readSignature(initialFilePath string) ([]byte, error) {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)

	sigFilePath := filepath.Join(dir, baseName+".sig")

	return os.ReadFile(sigFilePath)
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
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

	return publicKey, nil
}
