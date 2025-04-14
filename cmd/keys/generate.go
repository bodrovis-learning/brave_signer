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
)

// KeyGenConfig holds the command-specific configuration for key generation.
type KeyGenConfig struct {
	PrivKeyOutputPath    string `mapstructure:"priv-key-path"`
	PubKeyOutputPath     string `mapstructure:"pub-key-path"`
	SkipPEMPresenceCheck bool   `mapstructure:"skip-pem-presence-check"`
	SaltSize             int    `mapstructure:"salt-size"`
	Argon2Time           uint32 `mapstructure:"argon2-time"`
	Argon2Memory         uint32 `mapstructure:"argon2-memory"`
	Argon2Threads        uint8  `mapstructure:"argon2-threads"`
	Argon2KeyLen         uint32 `mapstructure:"argon2-key-len"`
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)

	// Define subcommand flags.
	keysGenerateCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to save the public key in PEM format")
	keysGenerateCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to save the private key in PEM format")
	keysGenerateCmd.Flags().Bool("skip-pem-presence-check", false, "Skip checking if keys already exist (may overwrite keys)")
	keysGenerateCmd.Flags().Int("salt-size", 16, "Salt size (in bytes) used for key derivation")
	keysGenerateCmd.Flags().Uint32("argon2-time", 1, "Time parameter for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("argon2-memory", 64, "Memory parameter (in megabytes) for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint8("argon2-threads", 4, "Number of threads for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("argon2-key-len", 32, "Length (in bytes) of the derived key for the Argon2id function")
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates an Ed25519 key pair.",
	Long: `Generate an Ed25519 key pair and store it in PEM files.
The private key is encrypted using a passphrase you enter,
employing AES encryption with Argon2 key derivation for strong security.

Files created:
- Encrypted private key (PEM format)
- Public key (PEM format)`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting keys generation...")

		// Bind the subcommand flags to the global Viper instance.
		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind keys generate flags")
		}

		// Unmarshal the command-specific config into our typed struct.
		var keyGenCfg KeyGenConfig
		if err := config.Conf.Unmarshal(&keyGenCfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal keys generate config")
		}

		// Resolve absolute paths.
		privKeyPath, err := filepath.Abs(keyGenCfg.PrivKeyOutputPath)
		if err != nil {
			logger.HaltOnErr(err, "cannot process private key path")
		}
		pubKeyPath, err := filepath.Abs(keyGenCfg.PubKeyOutputPath)
		if err != nil {
			logger.HaltOnErr(err, "cannot process public key path")
		}
		keyGenCfg.PrivKeyOutputPath = privKeyPath
		keyGenCfg.PubKeyOutputPath = pubKeyPath

		// Optionally, check if keys already exist.
		if !keyGenCfg.SkipPEMPresenceCheck {
			if err := checkKeysExistence(privKeyPath, pubKeyPath); err != nil {
				logger.HaltOnErr(err, "found issue when checking keys paths")
			}
		}

		logger.Info("Generating key pair...")
		if err := generateEd25519Keys(keyGenCfg); err != nil {
			logger.HaltOnErr(err, "cannot create key pair")
		}

		logger.Info("Key generation successful!")
		logger.Info(fmt.Sprintf("Private key created at: %s", privKeyPath))
		logger.Info(fmt.Sprintf("Public key created at: %s", pubKeyPath))
	},
}

// generateEd25519Keys handles the crypto logic.
func generateEd25519Keys(cfg KeyGenConfig) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key pair: %v", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return fmt.Errorf("failed to fetch passphrase: %v", err)
	}

	salt, err := makeSalt(cfg.SaltSize)
	if err != nil {
		return err
	}

	key, err := crypto_utils.DeriveKey(crypto_utils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       cfg.Argon2Time,
		Memory:     cfg.Argon2Memory,
		KeyLen:     cfg.Argon2KeyLen,
		Threads:    cfg.Argon2Threads,
	})
	if err != nil {
		return fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := crypto_utils.MakeCrypter(key)
	if err != nil {
		return fmt.Errorf("failed to create crypter: %v", err)
	}

	nonce, err := crypto_utils.MakeNonce(crypter)
	if err != nil {
		return fmt.Errorf("failed to make nonce: %v", err)
	}

	// Encrypt the private key.
	encryptedData := crypter.Seal(nil, nonce, privateKey, nil)
	encryptedPEMBlock := &pem.Block{
		Type:  "ENCRYPTED ED25519 PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce":                   base64.StdEncoding.EncodeToString(nonce),
			"Salt":                    base64.StdEncoding.EncodeToString(salt),
			"Key-Derivation-Function": "Argon2",
		},
	}

	if err := savePrivKeyToPEM(cfg.PrivKeyOutputPath, encryptedPEMBlock); err != nil {
		return err
	}

	publicKeyPem := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKey,
	}
	if err := savePubKeyToPEM(cfg.PubKeyOutputPath, publicKeyPem); err != nil {
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
	defer func() {
		if closeErr := privKeyFile.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close private key file")
		}
	}()

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
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn(closeErr, "cannot close public key file")
		}
	}()

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
