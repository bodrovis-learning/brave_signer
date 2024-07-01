package keys

import (
	"crypto/ed25519"
	"crypto/rand"
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

type KeyGenConfig struct {
	privKeyOutputPath string
	pubKeyOutputPath  string
	saltSize          int
	time              uint32
	memory            uint32
	threads           uint8
	argon2KeyLen      uint32
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)

	// Configuration flags setup
	keysGenerateCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to save the public key in PEM format")
	keysGenerateCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to save the private key in PEM format")
	keysGenerateCmd.Flags().Bool("skip-pem-presence-check", false, "Skip checking if private and/or public keys already exist. Setting this option to true might result in overwriting your existing key pair")
	keysGenerateCmd.Flags().Int("salt-size", 16, "Salt size (in bytes) used in the Argon2 key derivation process")
	keysGenerateCmd.Flags().Uint32("argon2-time", 1, "Time parameter for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("argon2-memory", 64, "Memory parameter (in megabytes) for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint8("argon2-threads", 4, "Number of threads used in the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("argon2-key-len", 32, "Length of the derived key (in bytes) for the Argon2id key derivation function")
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates an Ed25519 key pair.",
	Long: `Generate an Ed25519 key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with the Argon2 key derivation function is utilized for strong security.

The following files will be created:
- A private key file (encrypted) in PEM format.
- A public key file in PEM format.
`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting keys generation...")

		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		privKeyPath, err := filepath.Abs(localViper.GetString("priv-key-path"))
		if err != nil {
			logger.HaltOnErr(err, "cannot process private key path")
		}

		pubKeyPath, err := filepath.Abs(localViper.GetString("pub-key-path"))
		if err != nil {
			logger.HaltOnErr(err, "cannot process public key path")
		}

		if !localViper.GetBool("skip-pem-presence-check") {
			err = checkKeysExistence(privKeyPath, pubKeyPath)
			if err != nil {
				logger.HaltOnErr(err, "found issue when checking keys paths")
			}
		}

		pkGenConfig := KeyGenConfig{
			privKeyOutputPath: privKeyPath,
			pubKeyOutputPath:  pubKeyPath,
			saltSize:          localViper.GetInt("salt-size"),
			time:              localViper.GetUint32("argon2-time"),
			memory:            localViper.GetUint32("argon2-memory"),
			threads:           uint8(localViper.GetUint("argon2-threads")),
			argon2KeyLen:      localViper.GetUint32("argon2-key-len"),
		}

		logger.Info("Generating key pair...")

		err = generateEd25519Keys(pkGenConfig)
		logger.HaltOnErr(err, "cannot create key pair")

		logger.Info("Key generation successful!")
		logger.Info(fmt.Sprintf("Private key created at: %s\n", privKeyPath))
		logger.Info(fmt.Sprintf("Public key created at: %s\n", pubKeyPath))
	},
}

func generateEd25519Keys(keyConfig KeyGenConfig) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key pair: %v", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return fmt.Errorf("failed to fetch passphrase: %v", err)
	}

	salt, err := makeSalt(keyConfig.saltSize)
	if err != nil {
		return err
	}

	key, err := crypto_utils.DeriveKey(crypto_utils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       keyConfig.time,
		Memory:     keyConfig.memory,
		KeyLen:     keyConfig.argon2KeyLen,
		Threads:    keyConfig.threads,
	})
	if err != nil {
		return fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := crypto_utils.MakeCrypter(key)
	if err != nil {
		return fmt.Errorf("failed to create crypter: %v", err)
	}

	// Create a nonce for AES-GCM
	nonce, err := crypto_utils.MakeNonce(crypter)
	if err != nil {
		return fmt.Errorf("failed to make nonce: %v", err)
	}

	// Encrypt the private key
	encryptedData := crypter.Seal(nil, nonce, privateKey, nil)

	// Create a PEM block with the encrypted data
	encryptedPEMBlock := &pem.Block{
		Type:  "ENCRYPTED ED25519 PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce":                   base64.StdEncoding.EncodeToString(nonce),
			"Salt":                    base64.StdEncoding.EncodeToString(salt),
			"Key-Derivation-Function": "Argon2",
		},
	}

	err = savePrivKeyToPEM(keyConfig.privKeyOutputPath, encryptedPEMBlock)
	if err != nil {
		return err
	}

	// Save the public key as well, if needed
	publicKeyPem := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKey,
	}
	err = savePubKeyToPEM(keyConfig.pubKeyOutputPath, publicKeyPem)
	if err != nil {
		return err
	}

	return nil
}

func checkKeysExistence(privKeyPath, pubKeyPath string) error {
	if err := checkKeyExistence(privKeyPath, "private"); err != nil {
		return err
	}
	if err := checkKeyExistence(pubKeyPath, "public"); err != nil {
		return err
	}
	return nil
}

func checkKeyExistence(keyPath, keyType string) error {
	pathInfo, err := utils.CheckPathInfo(keyPath)
	if err != nil {
		return fmt.Errorf("failed to check %s key path: %v", keyType, err)
	}
	if pathInfo != nil && !pathInfo.IsDir() {
		return fmt.Errorf("%s key already exists at: %s (you can suppress this check by setting --skip-pem-presence-check to true)", keyType, keyPath)
	}
	return nil
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

func savePubKeyToPEM(outputPath string, pemBlock *pem.Block) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer file.Close()

	err = pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to write public key PEM: %v", err)
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
