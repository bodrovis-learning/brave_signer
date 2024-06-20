package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/logger"
	"brave_signer/pkg/crypto_utils"
	"brave_signer/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type PrivateKeyGen struct {
	outputPath   string
	keyBitSize   int
	saltSize     int
	time         uint32
	memory       uint32
	threads      uint8
	argon2KeyLen uint32
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)

	// Configuration flags setup
	keysGenerateCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to save the public key")
	keysGenerateCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to save the private key")
	keysGenerateCmd.Flags().Int("priv-key-size", 2048, "Private key size in bits")
	keysGenerateCmd.Flags().Int("salt-size", 16, "Salt size used in key derivation in bytes")
	keysGenerateCmd.Flags().Uint32("argon2-time", 1, "Time parameter used in Argon2id")
	keysGenerateCmd.Flags().Uint32("argon2-memory", 64, "Memory parameter (megabytes) used in Argon2id")
	keysGenerateCmd.Flags().Uint8("argon2-threads", 4, "Threads parameter used in Argon2id")
	keysGenerateCmd.Flags().Uint32("argon2-key-len", 32, "Key length parameter used in Argon2id")
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates key pair.",
	Long:  `Generate an RSA key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with Argon2 key derivation function is utilized.`,
	Run: func(cmd *cobra.Command, args []string) {
		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		pkGenConfig := PrivateKeyGen{
			outputPath:   localViper.GetString("priv-key-path"),
			keyBitSize:   localViper.GetInt("priv-key-size"),
			saltSize:     localViper.GetInt("salt-size"),
			time:         localViper.GetUint32("argon2-time"),
			memory:       localViper.GetUint32("argon2-memory"),
			threads:      uint8(localViper.GetUint("argon2-threads")),
			argon2KeyLen: localViper.GetUint32("argon2-key-len"),
		}

		logger.Info("Generating private key...")

		privateKey, err := generatePrivKey(pkGenConfig)
		logger.HaltOnErr(err, "cannot create priv key")

		logger.Info("Generating public key...")

		err = generatePubKey(localViper.GetString("pub-key-path"), privateKey)
		logger.HaltOnErr(err, "cannot create pub key")
	},
}

func generatePrivKey(pkGenConfig PrivateKeyGen) (*rsa.PrivateKey, error) {
	absPath, err := filepath.Abs(pkGenConfig.outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, pkGenConfig.keyBitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch passphrase: %v", err)
	}

	// Marshal the private key to DER format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := makeSalt(pkGenConfig.saltSize)
	if err != nil {
		return nil, err
	}

	key, err := crypto_utils.DeriveKey(crypto_utils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       pkGenConfig.time,
		Memory:     pkGenConfig.memory,
		KeyLen:     pkGenConfig.argon2KeyLen,
		Threads:    pkGenConfig.threads,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := crypto_utils.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cryper: %v", err)
	}

	// Create a nonce for AES-GCM
	nonce, err := crypto_utils.MakeNonce(crypter)
	if err != nil {
		return nil, fmt.Errorf("failed to make nonce: %v", err)
	}

	// Encrypt the private key
	encryptedData := crypter.Seal(nil, nonce, privateKeyBytes, nil)

	// Create a PEM block with the encrypted data
	encryptedPEMBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce":                   base64.StdEncoding.EncodeToString(nonce),
			"Salt":                    base64.StdEncoding.EncodeToString(salt),
			"Key-Derivation-Function": "Argon2",
		},
	}

	err = savePrivKeyToPEM(absPath, encryptedPEMBlock)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func savePrivKeyToPEM(absPath string, encryptedPEMBlock *pem.Block) error {
	privKeyFile, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privKeyFile.Close()

	if err := pem.Encode(privKeyFile, encryptedPEMBlock); err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %v", err)
	}

	return nil
}

func generatePubKey(path string, privKey *rsa.PrivateKey) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	file, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1}); err != nil {
		return fmt.Errorf("failed to encode public key to PEM: %v", err)
	}

	return nil
}

// makeSalt generates a cryptographic salt.
func makeSalt(saltSize int) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	return salt, nil
}
