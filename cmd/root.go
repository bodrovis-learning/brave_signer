package cmd

import (
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "brave_signer",
		Short: "Description of brave_signer",
		Long:  `Long description of brave_signer.`,
	}
}
