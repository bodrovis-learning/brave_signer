package keys

import (
	"fmt"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/keys"
	"brave_signer/internal/logger"

	"github.com/spf13/cobra"
)

// KeyGenConfig holds the command-specific configuration for key generation.
type KeyGenConfig struct {
	PrivKeyOutputPath    string `mapstructure:"priv-key-path"`
	PubKeyOutputPath     string `mapstructure:"pub-key-path"`
	SkipPEMPresenceCheck bool   `mapstructure:"skip-pem-presence-check"`
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)

	keysGenerateCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to save the public key in PEM format")
	keysGenerateCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to save the private key in PEM format")
	keysGenerateCmd.Flags().Bool("skip-pem-presence-check", false, "Skip checking if keys already exist (may overwrite keys)")
	keysGenerateCmd.Flags().Int("crypto.salt-size", 16, "Salt size (in bytes) used for key derivation")
	keysGenerateCmd.Flags().Uint32("crypto.argon2-time", 1, "Time parameter for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("crypto.argon2-memory", 64, "Memory parameter (in megabytes) for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint8("crypto.argon2-threads", 4, "Number of threads for the Argon2id key derivation function")
	keysGenerateCmd.Flags().Uint32("crypto.argon2-key-len", 32, "Length (in bytes) of the derived key for the Argon2id function")
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

		if err := config.Conf.BindPFlags(cmd.Flags()); err != nil {
			logger.HaltOnErr(err, "failed to bind keys generate flags")
		}

		var keyGenCfg KeyGenConfig
		if err := config.Conf.Unmarshal(&keyGenCfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal command config")
		}

		cryptoCfg := keys.BuildCryptoConfigFromFlags()

		privKeyPath, err := filepath.Abs(keyGenCfg.PrivKeyOutputPath)
		if err != nil {
			logger.HaltOnErr(err, "cannot process private key path")
		}
		pubKeyPath, err := filepath.Abs(keyGenCfg.PubKeyOutputPath)
		if err != nil {
			logger.HaltOnErr(err, "cannot process public key path")
		}

		privateKey, publicKey := keys.InitEmptyKeyPair(privKeyPath, pubKeyPath)

		if !keyGenCfg.SkipPEMPresenceCheck {
			if err := keys.CheckExistence(privateKey, publicKey); err != nil {
				logger.HaltOnErr(err, "key files already exist")
			}
		}

		if err := keys.PopulateKeyPair(privateKey, publicKey); err != nil {
			logger.HaltOnErr(err, "failed to generate keypair")
		}

		if err := privateKey.SealWithPassphrase(cryptoCfg); err != nil {
			logger.HaltOnErr(err, "encryption failed")
		}

		if err := privateKey.SavePEMToFile(); err != nil {
			logger.HaltOnErr(err, "failed to write private key")
		}

		if err := publicKey.SavePEMToFile(); err != nil {
			logger.HaltOnErr(err, "failed to write public key")
		}

		logger.Info("Key generation successful!")
		logger.Info(fmt.Sprintf("Private key created at: %s", privKeyPath))
		logger.Info(fmt.Sprintf("Public key created at: %s", pubKeyPath))
		logger.Info(fmt.Sprintf("Public key fingerprint (SHA-256): %s", publicKey.FingerprintBase64()))
	},
}
