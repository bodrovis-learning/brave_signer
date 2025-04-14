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
)

// VerifyFileConfig holds the command-specific configuration for verifying a signature.
// It also includes persistent options (file path and hash algorithm) inherited from the parent signatures command.
type VerifyFileConfig struct {
	PubKeyPath string `mapstructure:"pub-key-path"`
	FilePath   string `mapstructure:"file-path"`
	HashAlgo   string `mapstructure:"hash-algo"`
}

func init() {
	// Attach the verifyfile command to the main signatures command.
	signaturesCmd.AddCommand(signaturesVerifyFileCmd)

	// Define subcommand-specific flags.
	signaturesVerifyFileCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to the Ed25519 public key in PEM format")
}

var signaturesVerifyFileCmd = &cobra.Command{
	Use:   "verifyfile",
	Short: "Verify the signature of a file.",
	Long: `Verify the digital signature of a specified file using an Ed25519 public key. 
The command expects a signature file named "<original_filename>.sig" in the same directory 
as the file being verified. The public key should be in PEM format.

Process:
1. Load the Ed25519 public key.
2. Read the signature from the .sig file.
3. Hash the file using the specified hash algorithm.
4. Verify the signature against the file hash.
`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting signature verification process...")

		// Bind the subcommand flags to the global Viper instance.
		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind verifyfile flags")
		}

		// Unmarshal the configuration into our typed struct.
		var cfg VerifyFileConfig
		if err := config.Conf.Unmarshal(&cfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal verifyfile config")
		}

		// Process the public key file path.
		fullPubKeyPath, err := utils.ProcessFilePath(cfg.PubKeyPath)
		logger.HaltOnErr(err, "failed to process public key path")

		// Load the public key.
		publicKey, err := loadPublicKey(fullPubKeyPath)
		logger.HaltOnErr(err, "cannot load public key from file")

		// Process the file path.
		fullFilePath, err := utils.ProcessFilePath(cfg.FilePath)
		logger.HaltOnErr(err, "failed to process file path")

		// Read the signature from the .sig file.
		signatureRaw, err := readSignature(fullFilePath)
		logger.HaltOnErr(err, "cannot read signature")

		// Get the hash function based on the provided hash algorithm.
		hasher, hashType := getHashFunction(cfg.HashAlgo)

		// Hash the file.
		digest, err := hashFile(fullFilePath, hasher)
		logger.HaltOnErr(err, "cannot hash file")

		// Verify the signature.
		signerInfo, err := verifyFileSignature(publicKey, digest, signatureRaw)
		logger.HaltOnErr(err, "cannot verify signature")

		logger.Info(fmt.Sprintf("Verification successful for file: %s", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf("Verified using public key: %s", filepath.Base(fullPubKeyPath)))
		logger.Info(fmt.Sprintf("Hash Algorithm: %s", hashType.String()))
		logger.Info(fmt.Sprintf("Signer info:\n%s", signerInfo))
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
