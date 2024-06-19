package main

import (
	"brave_signer/cmd"
	"brave_signer/cmd/keys"
	"brave_signer/cmd/signatures"
	"brave_signer/logger"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func main() {
	rootCmd := cmd.RootCmd()
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:    "gendocs",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateDocs(rootCmd, "./docs"); err != nil {
				fmt.Println("Error generating docs:", err)
			}
		},
	})

	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnErr(errors.New("cannot proceed, exiting now"), "Initial setup failed")
	}
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	// Ensure the base directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Generate markdown documentation for all commands
	return doc.GenMarkdownTree(rootCmd, dir)
}
