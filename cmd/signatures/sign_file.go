package signatures

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/logger"
	"brave_signer/pkg/crypto_utils"
	"brave_signer/pkg/utils"

	"github.com/spf13/cobra"
)

// SignFileConfig holds the configuration for signing a file.
// It merges command-specific settings and shared settings (file path and hash algorithm come
// from persistent flags defined in the parent "signatures" command).
type SignFileConfig struct {
	// Command-specific flags.
	PrivKeyPath   string `mapstructure:"priv-key-path"`
	SignerID      string `mapstructure:"signer-id"`
	Argon2Time    uint32 `mapstructure:"argon2-time"`
	Argon2Memory  uint32 `mapstructure:"argon2-memory"`
	Argon2Threads uint8  `mapstructure:"argon2-threads"`
	Argon2KeyLen  uint32 `mapstructure:"argon2-key-len"`

	// Inherited persistent flags.
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
}

// PkLoadConfig is used to load the private key.
type PkLoadConfig struct {
	pkPath       string
	time         uint32
	memory       uint32
	threads      uint8
	argon2KeyLen uint32
}

func init() {
	// Attach the signfile command to the main signatures command.
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	// Define subcommand–specific flags.
	signaturesSignFileCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to your Ed25519 private key in PEM format")
	signaturesSignFileCmd.Flags().String("signer-id", "", "Signer's name or identifier")
	signaturesSignFileCmd.Flags().Uint32("argon2-time", 1, "Time parameter used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("argon2-memory", 64, "Memory parameter (in megabytes) used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint8("argon2-threads", 4, "Number of threads used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("argon2-key-len", 32, "Length of the derived key (in bytes) for the Argon2id key derivation function")
}

// validateSignerID checks that the signer identifier is a reasonable length.
func validateSignerID(signerID string) error {
	const (
		minSignerInfoLength = 1
		maxSignerInfoLength = 65535
	)
	if len(signerID) < minSignerInfoLength || len(signerID) > maxSignerInfoLength {
		return fmt.Errorf("signer information must be between %d and %d characters", minSignerInfoLength, maxSignerInfoLength)
	}
	return nil
}

var signaturesSignFileCmd = &cobra.Command{
	Use:   "signfile",
	Short: "Sign the file.",
	Long: `Sign the specified file using an Ed25519 private key and store the signature in a .sig file.
You'll be asked for a passphrase to decrypt the private key.

Process:
1. Load and decrypt the private key.
2. Hash the file using the designated hash algorithm.
3. Sign the file hash.
4. Write the signature (plus signer info) to a .sig file in the same directory.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate the signer identifier.
		signerID := cmd.Flag("signer-id").Value.String()
		return validateSignerID(signerID)
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting signing process...")

		// Bind subcommand flags to the global Viper instance.
		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind signfile flags")
		}

		// Unmarshal the configuration into our typed struct.
		var cfg SignFileConfig
		if err := config.Conf.Unmarshal(&cfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal signfile config")
		}

		// Process private key file path.
		fullPrivKeyPath, err := utils.ProcessFilePath(cfg.PrivKeyPath)
		logger.HaltOnErr(err, "failed to process private key path")

		// Prepare private key load configuration.
		pkCfg := PkLoadConfig{
			pkPath:       fullPrivKeyPath,
			time:         cfg.Argon2Time,
			memory:       cfg.Argon2Memory,
			threads:      cfg.Argon2Threads,
			argon2KeyLen: cfg.Argon2KeyLen,
		}

		// Load and decrypt the private key.
		privateKey, err := loadPrivateKey(pkCfg)
		logger.HaltOnErr(err, "cannot load private key from file")

		// Process the file to be signed.
		fullFilePath, err := utils.ProcessFilePath(cfg.FilePath)
		logger.HaltOnErr(err, "failed to process file path")

		// Obtain the hash function based on the hash algorithm.
		hasher, _ := getHashFunction(cfg.HashAlgo)

		// Hash the target file.
		digest, err := hashFile(fullFilePath, hasher)
		logger.HaltOnErr(err, "cannot hash the file")

		// Sign the file digest.
		signature := signMessage(digest, privateKey)

		// Package the signature along with the signer information.
		signaturePackage, err := makeSignaturePackage(signature, cfg.SignerID)
		logger.HaltOnErr(err, "cannot make signature package")

		// Write the signature package to a .sig file.
		fullSigPath, err := writeSignatureToFile(signaturePackage, fullFilePath)
		logger.HaltOnErr(err, "cannot write signature to file")

		logger.Info(fmt.Sprintf("Signature generation successful for file: %s", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf(".sig file created at: %s", fullSigPath))
	},
}

func makeSignaturePackage(signature []byte, signerInfo string) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfo))); err != nil {
		return nil, fmt.Errorf("failed to write signer info length: %v", err)
	}

	if _, err := buf.WriteString(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to write signer info: %v", err)
	}

	if _, err := buf.Write(signature); err != nil {
		return nil, fmt.Errorf("failed to write signature: %v", err)
	}

	return buf.Bytes(), nil
}

func writeSignatureToFile(signaturePackage []byte, initialFilePath string) (string, error) {
	sigFilePath := filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")

	if err := os.WriteFile(sigFilePath, signaturePackage, 0o644); err != nil {
		return "", err
	}

	return sigFilePath, nil
}

func signMessage(message []byte, privateKey ed25519.PrivateKey) []byte {
	signature := ed25519.Sign(privateKey, message)
	return signature
}

func decodePEMFile(pkPath string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(pkPath)
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

func loadPrivateKey(config PkLoadConfig) (ed25519.PrivateKey, error) {
	block, err := decodePEMFile(config.pkPath)
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
	key, err := crypto_utils.DeriveKey(crypto_utils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       config.time,
		Memory:     config.memory,
		KeyLen:     config.argon2KeyLen,
		Threads:    config.threads,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := crypto_utils.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to make crypter: %v", err)
	}

	// Decrypt the private key
	plaintext, err := crypter.Open(nil, []byte(nonce), block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("private key file decryption failed: %v", err)
	}

	// Parse the Ed25519 private key
	privateKey := ed25519.PrivateKey(plaintext)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return privateKey, nil
}
