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

// VerifyFileConfig holds the command-specific configuration for verifying a signature.
// It also includes persistent options (file path and hash algorithm) inherited from the parent signatures command.
type VerifyFileConfig struct {
	PubKeyPath string `mapstructure:"pub-key-path"`

	// Inherited persistent flags.
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
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

		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind verifyfile flags")
		}

		var cfg VerifyFileConfig
		if err := config.Conf.Unmarshal(&cfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal verifyfile config")
		}

		fullFilePath, err := utils.ProcessFilePath(cfg.FilePath)
		logger.HaltOnErr(err, "failed to process file path")

		fullPubKeyPath, err := utils.ProcessFilePath(cfg.PubKeyPath)
		logger.HaltOnErr(err, "failed to process public key path")

		publicKey, err := keys.LoadPublicFromPEMFile(fullPubKeyPath)
		logger.HaltOnErr(err, "cannot load public key from file")

		signature, err := signatures.LoadRawFromSIGFile(fullFilePath)
		logger.HaltOnErr(err, "signature file not found or unreadable (expected <file>.sig)")

		hasher := hashers.New(cfg.HashAlgo)

		digest, err := hasher.HashFile(fullFilePath)
		logger.HaltOnErr(err, "cannot hash file")

		signerInfo, err := signature.VerifyDigest(digest, publicKey)
		logger.HaltOnErr(err, "cannot verify signature")

		logger.Info(fmt.Sprintf("Verification successful for file: %s", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf("Verified using public key: %s", filepath.Base(fullPubKeyPath)))
		logger.Info(fmt.Sprintf("Public key fingerprint (SHA-256): %s", publicKey.FingerprintBase64()))
		logger.Info(fmt.Sprintf("Hash Algorithm: %s", hasher.HashType.String()))
		logger.Info(fmt.Sprintf("Signer info:\n%s", signerInfo))
	},
}
