package signatures

import (
	"brave_signer/utils"
	"crypto"
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
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	signaturesSignFileCmd.Flags().String("priv-key", "priv_key.pem", "Path to your private key")
	signaturesSignFileCmd.Flags().String("file", "", "Path to the file that should be signed")
	signaturesSignFileCmd.MarkFlagRequired("file")
}

var signaturesSignFileCmd = &cobra.Command{
	Use:   "signfile",
	Short: "Sign the file",
	Long:  `This command signs the specified file using an RSA private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		privPath, err := cmd.Flags().GetString("priv-key")
		utils.HaltOnErr(err)
		filePath, err := cmd.Flags().GetString("file")
		utils.HaltOnErr(err)

		fullFilePath, err := utils.ProcessFilePath(filePath)
		utils.HaltOnErr(err)

		fullPrivKeyPath, err := utils.ProcessFilePath(privPath)
		utils.HaltOnErr(err)

		privateKey, err := loadPrivateKey(fullPrivKeyPath)
		utils.HaltOnErr(err)

		digest, err := hashFile(fullFilePath)
		utils.HaltOnErr(err)

		signature, err := signDigest(digest, privateKey)
		utils.HaltOnErr(err)

		err = writeSignatureToFile(signature, fullFilePath)
		utils.HaltOnErr(err)
	},
}

func writeSignatureToFile(signature []byte, initialFilePath string) error {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)
	extension := filepath.Ext(baseName)
	nameWithoutExt := baseName[:len(baseName)-len(extension)]

	sigFilePath := filepath.Join(dir, nameWithoutExt+".sig")

	return os.WriteFile(sigFilePath, signature, 0644)
}

func signDigest(digest []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA3_256, digest, opts)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func loadPrivateKey(pkPath string) (*rsa.PrivateKey, error) {
	fileBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(fileBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM file")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM file: extra data encountered after PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
