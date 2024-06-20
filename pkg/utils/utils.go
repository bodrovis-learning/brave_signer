package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

// ProcessFilePath converts a given path to an absolute path and verifies it points to a regular file.
func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("converting to absolute path: %v", err)
	}

	fileInfo, err := os.Stat(absolutePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path '%s' does not exist", path)
		}
		return "", fmt.Errorf("fetching path info: %v", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("path '%s' does not point to a file", path)
	}

	return absolutePath, nil
}

// GetPassphrase prompts the user for a passphrase and securely reads it.
func GetPassphrase() (passphrase []byte, err error) {
	fmt.Println("Enter passphrase:")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to set terminal to raw mode: %v", err)
	}
	defer func() {
		if restoreErr := safeRestore(int(os.Stdin.Fd()), oldState); restoreErr != nil {
			err = fmt.Errorf("failed to restore terminal: %v", restoreErr)
		}
	}()

	passphrase, err = term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %v", err)
	}

	return passphrase, nil
}

// safeRestore attempts to restore the terminal to its original state and logs an error if it fails.
func safeRestore(fd int, state *term.State) error {
	if err := term.Restore(fd, state); err != nil {
		return fmt.Errorf("safe restoration error: %v", err)
	}

	return nil
}
