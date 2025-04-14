package keys

import (
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage key pairs.",
	Long: `The keys command provides subcommands to create and manage Ed25519 public/private key pairs in PEM files.

Subcommands:
- generate: Generate a new Ed25519 key pair and store them in PEM files.

Features:
- Generate secure Ed25519 key pairs.
- Store keys in PEM files with encryption for private keys.
`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

// Init initializes keys commands
func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(keysCmd)
}
