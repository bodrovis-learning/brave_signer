package utils

import (
	"fmt"
	"golang.org/x/term"
	"log"
	"os"
	"path/filepath"
)

var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags|log.Lshortfile)

func safeRestore(fd int, state *term.State) {
	if err := term.Restore(fd, state); err != nil {
		// Handle the error, e.g., log it, return it if you're in a function that returns an error, etc.
		HaltOnErr(fmt.Errorf("failed to restore terminal state: %v", err))
	}
}

// GetPassphrase prompts the user for a passphrase and securely reads it.
func GetPassphrase() ([]byte, error) {
	fmt.Println("Enter passphrase:")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to grab passphrase: %w", err)
	}

	defer safeRestore(int(os.Stdin.Fd()), oldState)

	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to grab passphrase: %w", err)
	}

	return passphrase, nil
}

// HaltOnErr logs an error and exits if the error is non-nil.
func HaltOnErr(err error, messages ...string) {
	if err != nil {
		message := "An error occurred"

		if len(messages) > 0 && messages[0] != "" {
			message = messages[0]
		}

		errorLogger.Printf("%s: %v", message, err)

		os.Exit(1)
	}
}

// ProcessFilePath converts a given path to an absolute path and verifies it points to a regular file.
func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("converting to absolute path: %w", err)
	}

	fileInfo, err := os.Stat(absolutePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path '%s' does not exist", path)
		}
		return "", fmt.Errorf("fetching path info: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("path '%s' does not point to a file", path)
	}

	return absolutePath, nil
}
