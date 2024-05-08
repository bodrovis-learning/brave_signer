package main

import (
	"brave_signer/cmd"
	"brave_signer/cmd/keys"
	"brave_signer/cmd/signatures"
	"brave_signer/utils"
)

func main() {
	rootCmd := cmd.RootCmd()
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		utils.HaltOnErr(err, "Initial setup failed")
	}
}
