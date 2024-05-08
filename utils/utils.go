package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags|log.Lshortfile)

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

func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)

	if err != nil {
		return "", fmt.Errorf("converting to absolute path: %w", err)
	}

	fileInfo, err := os.Stat(absolutePath)

	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist")
		}

		return "", fmt.Errorf("fetching path info: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("path does not point to a file")
	}

	return absolutePath, nil
}
