package keys

import (
	"brave_signer/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
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
	Long:  `This command generates public and private keys and stores them into PEM file.`,
	Run: func(cmd *cobra.Command, args []string) {
		pubPath, pubErr := cmd.Flags().GetString("pub-out")
		utils.HaltOnErr(pubErr)
		privPath, privErr := cmd.Flags().GetString("priv-out")
		utils.HaltOnErr(privErr)

		privateKey, err := generatePrivKey(privPath)
		utils.HaltOnErr(err)

		generatePubKey(pubPath, privateKey)
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

	println("Enter passphrase:")
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))

	if err != nil {
		return nil, fmt.Errorf("failed to grab passphrase: %w", err)
	}

	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to grab passphrase: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Marshal the private key to DER format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Generate a salt for the key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// Derive a key using Argon2
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

	// Create an AES cipher using the derived key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Wrap the cipher block in GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Create a nonce for AES-GCM
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Encrypt the private key
	encryptedData := aesgcm.Seal(nil, nonce, privateKeyBytes, nil)

	// Create a PEM block with the encrypted data
	encryptedPEMBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce":                   string(nonce),
			"Salt":                    string(salt),
			"Key-Derivation-Function": "Argon2",
		},
	}

	// privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	// privPEM := pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: privBytes,
	// }

	privKeyFile, err := os.Create(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privKeyFile.Close()

	if err := pem.Encode(privKeyFile, encryptedPEMBlock); err != nil {
		return nil, fmt.Errorf("failed to encode private key to PEM: %w", err)
	}

	return privateKey, nil
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
