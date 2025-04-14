package main

import (
	"fmt"

	"brave_signer/cmd"
	"brave_signer/internal/logger"
)

func main() {
	rootCmd := cmd.RootCmd()

	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnErr(fmt.Errorf("command failed: %v", err), "initial setup failed")
	}
}
