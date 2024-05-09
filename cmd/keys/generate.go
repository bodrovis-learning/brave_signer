package keys

import (
	"brave_signer/utils"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func init() {
	keysCmd.AddCommand(keysGenerateCmd)

	keysGenerateCmd.Flags().String("pub-out", "pub_key.pem", "Path to save the public key")
	keysGenerateCmd.Flags().String("priv-out", "priv_key.pem", "Path to save the private key")
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates key pair.",
	Long:  `Generate an RSA key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with Argon2 key derivation function is utilized.`,
	Run: func(cmd *cobra.Command, args []string) {
		pubPath, pubErr := cmd.Flags().GetString("pub-out")
		utils.HaltOnErr(pubErr)
		privPath, privErr := cmd.Flags().GetString("priv-out")
		utils.HaltOnErr(privErr)

		privateKey, err := generatePrivKey(privPath)
		utils.HaltOnErr(err)

		err = generatePubKey(pubPath, privateKey)
		utils.HaltOnErr(err)
	},
}

func generatePrivKey(path string) (*rsa.PrivateKey, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, err
	}

	// Marshal the private key to DER format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := utils.MakeSalt()
	if err != nil {
		return nil, err
	}

	key := utils.DeriveKey(passphrase, salt)

	crypter, err := utils.MakeCrypter(key)
	if err != nil {
		return nil, err
	}

	// Create a nonce for AES-GCM
	nonce, err := utils.MakeNonce(crypter)
	if err != nil {
		return nil, err
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
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privKeyFile.Close()

	if err := pem.Encode(privKeyFile, encryptedPEMBlock); err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %w", err)
	}

	return nil
}

func generatePubKey(path string, privKey *rsa.PrivateKey) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	publicKey := &privKey.PublicKey

	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	pubPEM := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}

	file, err := os.Create(absPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := pem.Encode(file, &pubPEM); err != nil {
		return err
	}

	return nil
}
