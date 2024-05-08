package signatures

import (
	"github.com/spf13/cobra"
)

var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Create and verify signatures.",
	Long:  `Use subcommands to create signature (.sig) with private key and verify signature with public key.`,
}

func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)
}
