package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ProcessFilePath converts a path to an absolute path and checks if the file exists
func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("converting to absolute path: %v", err)
	}

	pathInfo, err := GetPathInfo(absolutePath)
	if err != nil {
		return "", err
	}
	if pathInfo == nil {
		return "", fmt.Errorf("path '%s' does not exist", absolutePath)
	}
	if pathInfo.IsDir() {
		return "", fmt.Errorf("path '%s' is a directory, not a file", absolutePath)
	}

	return absolutePath, nil
}

func GetPathInfo(path string) (fs.FileInfo, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching file info: %v", err)
	}

	return fileInfo, nil
}
