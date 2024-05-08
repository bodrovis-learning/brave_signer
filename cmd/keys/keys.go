package keys

import (
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "",
	Long:  ``,
}

func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(keysCmd)
}
