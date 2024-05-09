package signatures

import (
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
)

func hashFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", filePath, err)
	}
	defer file.Close()

	hasher := sha3.New256()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("error while hashing file %s: %w", filePath, err)
	}

	return hasher.Sum(nil), nil
}
