package signatures

import (
	"fmt"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/hashers"
	"brave_signer/internal/keys"
	"brave_signer/internal/logger"
	"brave_signer/internal/signatures"
	"brave_signer/internal/utils"

	"github.com/spf13/cobra"
)

// SignFileConfig holds the configuration for signing a file.
// It merges command-specific settings and shared settings (file path and hash algorithm come
// from persistent flags defined in the parent "signatures" command).
type SignFileConfig struct {
	// Command-specific flags.
	PrivKeyPath string `mapstructure:"priv-key-path"`
	SignerID    string `mapstructure:"signer-id"`

	// Inherited persistent flags.
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
}

func init() {
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	signaturesSignFileCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to your Ed25519 private key in PEM format")
	signaturesSignFileCmd.Flags().String("signer-id", "", "Signer's name or identifier")
	signaturesSignFileCmd.Flags().Uint32("crypto.argon2-time", 1, "Time parameter used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("crypto.argon2-memory", 64, "Memory parameter (in megabytes) used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint8("crypto.argon2-threads", 4, "Number of threads used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("crypto.argon2-key-len", 32, "Length of the derived key (in bytes) for the Argon2id key derivation function")
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

		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind signfile flags")
		}

		var cfg SignFileConfig
		if err := config.Conf.Unmarshal(&cfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal signfile config")
		}

		cryptoCfg := keys.BuildCryptoConfigFromFlags()

		fullFilePath, err := utils.ProcessFilePath(cfg.FilePath)
		logger.HaltOnErr(err, "failed to process file path")

		fullPrivKeyPath, err := utils.ProcessFilePath(cfg.PrivKeyPath)
		logger.HaltOnErr(err, "failed to process private key path")

		privateKey, err := keys.LoadPrivateFromPEMFile(fullPrivKeyPath, cryptoCfg)
		logger.HaltOnErr(err, "cannot load private key from file")

		hasher := hashers.New(cfg.HashAlgo)

		digest, err := hasher.HashFile(fullFilePath)
		logger.HaltOnErr(err, "cannot hash the file")

		signature, err := signatures.New(privateKey.SignMessage(digest))
		logger.HaltOnErr(err, "cannot make signature")

		signature, err = signature.GeneratePackage(cfg.SignerID)
		logger.HaltOnErr(err, "cannot make signature package")

		signaturePath, err := signature.SaveToSIGFile(fullFilePath)
		logger.HaltOnErr(err, "cannot save signature to file")

		logger.Info(fmt.Sprintf("Signature generation successful for file: %s", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf(".sig file created at: %s", signaturePath))
	},
}
