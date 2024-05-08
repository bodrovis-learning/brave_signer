package keys

import (
	"brave_signer/utils"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	Short: "",
	Long:  ``,
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

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}

	privKeyFile, err := os.Create(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privKeyFile.Close()

	if err := pem.Encode(privKeyFile, &privPEM); err != nil {
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
