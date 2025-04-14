package signatures

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"

	"brave_signer/internal/config"
	"brave_signer/internal/logger"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
)

// SignatureData holds signature details.
type SignatureData struct {
	Signature []byte `json:"signature"`
	Signer    string `json:"signer"`
}

// HashFunctionMap maps algorithm names to hash constructors and their crypto.Hash values.
var HashFunctionMap = map[string]struct {
	Constructor func() hash.Hash
	Hash        crypto.Hash
}{
	"sha3-256": {sha3.New256, crypto.SHA3_256},
	"sha3-512": {sha3.New512, crypto.SHA3_512},
	"sha256":   {sha256.New, crypto.SHA256},
	"sha512":   {sha512.New, crypto.SHA512},
}

// Set default hash algorithm.
var (
	defaultHasherName   = "sha3-256"
	DefaultHashFunction = HashFunctionMap[defaultHasherName]
)

// SignatureConfig holds the command-specific configuration for signature operations.
type SignatureConfig struct {
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
}

// signaturesCmd represents the base command for signing operations.
var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Create and verify signatures.",
	Long: `The signatures command provides subcommands to create and verify digital signatures.

Features:
- Securely sign files to ensure their authenticity and integrity.
- Verify signatures to confirm the origin and integrity of files.
`,
	// For now, simply unmarshal the config and show it.
	Run: func(cmd *cobra.Command, args []string) {
		// Bind the persistent flags for this command to the global Viper instance.
		if err := config.Conf.BindPFlags(cmd.PersistentFlags()); err != nil {
			logger.HaltOnErr(err, "failed to bind signatures flags")
		}
		var sigCfg SignatureConfig
		if err := config.Conf.Unmarshal(&sigCfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal signatures config")
		}
		// Log the current configuration, or later, forward to subcommands.
		logger.Info(fmt.Sprintf("Signatures config: file-path='%s', hash-algo='%s'", sigCfg.FilePath, sigCfg.HashAlgo))
		// For now, just show help.
		_ = cmd.Help()
	},
}

// Init initializes the signatures command and sets up its flags.
func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)

	// Setup persistent flags for signatures.
	signaturesCmd.PersistentFlags().String("file-path", "", "Path to the file that should be signed or verified")
	signaturesCmd.PersistentFlags().String("hash-algo", defaultHasherName, "Hashing algorithm to use for signing and verification")
}

// hashFile reads and hashes a file’s content using the provided hasher.
func hashFile(filePath string, hasher hash.Hash) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %v", filePath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close file after hashing")
		}
	}()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("error while hashing file %s: %v", filePath, err)
	}

	return hasher.Sum(nil), nil
}

// getHashFunction returns the appropriate hash function based on the algorithm name.
func getHashFunction(algo string) (hash.Hash, crypto.Hash) {
	if hf, ok := HashFunctionMap[algo]; ok {
		return hf.Constructor(), hf.Hash
	}
	logger.Warn(fmt.Errorf("unsupported hash algorithm: %s, falling back to default (%s)", algo, defaultHasherName))
	return DefaultHashFunction.Constructor(), DefaultHashFunction.Hash
}
