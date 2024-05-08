package signatures

import (
	"brave_signer/utils"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
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

	// block, rest := pem.Decode(fileBytes)
	// if block == nil || block.Type != "RSA PRIVATE KEY" {
	// 	return nil, fmt.Errorf("failed to decode PEM file")
	// }

	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM file: extra data encountered after PEM block")
	}

	// Retrieve the nonce and salt from the headers
	nonce, ok := block.Headers["Nonce"]
	if !ok {
		return nil, fmt.Errorf("nonce not found in PEM headers")
	}
	salt, ok := block.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("salt not found in PEM headers")
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

	// Derive the key from the passphrase and salt
	key := argon2.IDKey([]byte(passphrase), []byte(salt), 1, 64*1024, 4, 32)

	// Create an AES cipher using the derived key
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in GCM mode
	aesgcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	// Decrypt the private key
	plaintext, err := aesgcm.Open(nil, []byte(nonce), block.Bytes, nil)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
