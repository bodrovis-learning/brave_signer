package signatures

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"brave_signer/utils"

	"github.com/spf13/cobra"
)

func init() {
	signaturesCmd.AddCommand(signaturesVerifyFileCmd)

	signaturesVerifyFileCmd.Flags().String("pub-key", "pub_key.pem", "Path to the public key")
	signaturesVerifyFileCmd.Flags().String("file", "", "Path to the file that should be verified")
	err := signaturesVerifyFileCmd.MarkFlagRequired("file")
	utils.HaltOnErr(err)
}

var signaturesVerifyFileCmd = &cobra.Command{
	Use:   "verifyfile",
	Short: "Verify the signature of a file.",
	Long:  `Verify the digital signature of a specified file using an RSA public key and the signature file. The signature file should have the same basename as the actual file and be stored in the same directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		pubPath, err := cmd.Flags().GetString("pub-key")
		utils.HaltOnErr(err)
		filePath, err := cmd.Flags().GetString("file")
		utils.HaltOnErr(err)

		fullFilePath, err := utils.ProcessFilePath(filePath)
		utils.HaltOnErr(err)

		fullPubKeyPath, err := utils.ProcessFilePath(pubPath)
		utils.HaltOnErr(err)

		publicKey, err := loadPublicKey(fullPubKeyPath)
		utils.HaltOnErr(err)

		signatureRaw, err := readSignature(fullFilePath)
		utils.HaltOnErr(err)

		digest, err := hashFile(fullFilePath)
		utils.HaltOnErr(err)

		signerInfo, err := verifyFileSignature(publicKey, digest, signatureRaw)
		utils.HaltOnErr(err)

		fmt.Println("Verification successful!")
		fmt.Printf("Signer info:\n%s\n", signerInfo)
	},
}

func verifyFileSignature(publicKey *rsa.PublicKey, digest []byte, signatureRaw []byte) ([]byte, error) {
	buf := bytes.NewReader(signatureRaw)

	var nameLength uint32
	if err := binary.Read(buf, binary.BigEndian, &nameLength); err != nil {
		return nil, fmt.Errorf("failed to read signer info length: %w", err)
	}

	// Read the signer info
	signerInfo := make([]byte, nameLength)
	if _, err := buf.Read(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to read signer info: %w", err)
	}

	// The rest of the buffer is the signature
	signature := make([]byte, buf.Len())
	if _, err := buf.Read(signature); err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	err := rsa.VerifyPSS(publicKey, crypto.SHA3_256, digest, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return signerInfo, nil
}

func readSignature(initialFilePath string) ([]byte, error) {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)
	extension := filepath.Ext(baseName)
	nameWithoutExt := baseName[:len(baseName)-len(extension)]

	sigFilePath := filepath.Join(dir, nameWithoutExt+".sig")

	return os.ReadFile(sigFilePath)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("public key file does not contain a valid PEM block")
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("additional data found after the first PEM block, which could indicate multiple PEM blocks or corrupted data")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("public key file does not contain an RSA public key")
	}
}
