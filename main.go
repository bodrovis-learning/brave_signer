package main

import (
	"brave_signer/cmd"
	"brave_signer/cmd/keys"
	"brave_signer/cmd/signatures"
	"brave_signer/logger"
)

func main() {
	rootCmd := cmd.RootCmd()
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnErr(err, "Initial setup failed")
	}
}
