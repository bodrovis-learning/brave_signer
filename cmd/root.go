package cmd

import (
	"context"
	"fmt"
	"os"

	"brave_signer/cmd/keys"
	"brave_signer/cmd/signatures"
	"brave_signer/internal/config"
	"brave_signer/internal/logger"

	"github.com/spf13/cobra/doc"

	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "brave_signer",
		Short:        "Bravely generate key pairs, sign files, and check signatures.",
		Long:         `A collection of tools to generate key pairs in PEM files, sign files, and verify signatures.`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd, config.ConfigParams{
				Name: cmd.Flag("config-file-name").Value.String(),
				Type: cmd.Flag("config-file-type").Value.String(),
				Path: cmd.Flag("config-path").Value.String(),
			})
		},
	}

	rootCmd.PersistentFlags().String("config-file-name", "config", "Your config file name.")
	rootCmd.PersistentFlags().String("config-file-type", "yaml", "Your config file type.")
	rootCmd.PersistentFlags().String("config-path", ".", "Config file location.")

	// Add subcommands
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	// Add hidden docs command
	rootCmd.AddCommand(&cobra.Command{
		Use:    "gendocs",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateDocs(rootCmd, "./docs"); err != nil {
				logger.Warn(fmt.Errorf("error generating docs: %v", err))
			}
		},
	})

	return rootCmd
}

func initializeConfig(cmd *cobra.Command, params config.ConfigParams) error {
	localViper, err := config.LoadFromFile(params)
	if err != nil {
		return err
	}

	if err := config.BindFlags(cmd, localViper); err != nil {
		return err
	}

	ctx := context.WithValue(cmd.Context(), config.ViperKey, localViper)
	cmd.SetContext(ctx)
	return nil
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	// Ensure the base directory exists
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Generate markdown documentation for all commands
	return doc.GenMarkdownTree(rootCmd, dir)
}
