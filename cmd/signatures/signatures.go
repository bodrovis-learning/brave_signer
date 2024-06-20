package signatures

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"

	"brave_signer/internal/logger"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
)

type SignatureData struct {
	Signature []byte `json:"signature"`
	Signer    string `json:"signer"`
}

// HashFunctionMap maps algorithm names to hash constructors and corresponding crypto.Hash values
var HashFunctionMap = map[string]struct {
	constructor func() hash.Hash
	hash        crypto.Hash
}{
	"sha3-256": {sha3.New256, crypto.SHA3_256},
	"sha3-512": {sha3.New512, crypto.SHA3_512},
	"sha256":   {sha256.New, crypto.SHA256},
	"sha512":   {sha512.New, crypto.SHA512},
}

// defaultHasherName specifies the default hash algorithm name
var defaultHasherName = "sha3-256"

// DefaultHashFunction specifies the default hash algorithm
var DefaultHashFunction = HashFunctionMap[defaultHasherName]

// signaturesCmd represents the base command for signing operations
var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Create and verify signatures.",
	Long:  `Use subcommands to create signature (.sig) with private key and verify signature with public key.`,
}

// Init initializes signatures commands
func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)

	// Initialize persistent flags
	signaturesCmd.PersistentFlags().String("file-path", "", "Path to the file that should be signed")
	signaturesCmd.PersistentFlags().String("hash-algo", defaultHasherName, "Hashing algorithm to use")
}

// hashFile hashes the content of a file using the specified hash function
func hashFile(filePath string, hasher hash.Hash) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %v", filePath, err)
	}
	defer file.Close()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("error while hashing file %s: %v", filePath, err)
	}

	return hasher.Sum(nil), nil
}

// getHashFunction returns the appropriate hash function based on the algorithm name
func getHashFunction(algo string) (hash.Hash, crypto.Hash) {
	if hf, ok := HashFunctionMap[algo]; ok {
		return hf.constructor(), hf.hash
	}
	logger.Warn(fmt.Errorf("unsupported hash algorithm: %s, falling back to default (%s)", algo, defaultHasherName))
	return DefaultHashFunction.constructor(), DefaultHashFunction.hash
}
