package signatures

import (
	"brave_signer/internal/config"
	"brave_signer/internal/hashers"
	"brave_signer/internal/logger"

	"github.com/spf13/cobra"
)

// SignatureConfig holds the command-specific configuration for signature operations.
type SignatureConfig struct {
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
}

// signaturesCmd represents the base command for signing operations.
var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Create and verify signatures.",
	Long: `The signatures command provides subcommands to create and verify digital signatures.

Features:
- Securely sign files to ensure their authenticity and integrity.
- Verify signatures to confirm the origin and integrity of files.
`,
	// For now, simply unmarshal the config and show it.
	Run: func(cmd *cobra.Command, args []string) {
		// Bind the persistent flags for this command to the global Viper instance.
		if err := config.Conf.BindPFlags(cmd.PersistentFlags()); err != nil {
			logger.HaltOnErr(err, "failed to bind signatures flags")
		}
		var sigCfg SignatureConfig
		if err := config.Conf.Unmarshal(&sigCfg); err != nil {
			logger.HaltOnErr(err, "failed to unmarshal signatures config")
		}

		_ = cmd.Help()
	},
}

// Init initializes the signatures command and sets up its flags.
func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)

	// Setup persistent flags for signatures.
	signaturesCmd.PersistentFlags().String("file-path", "", "Path to the file that should be signed or verified")
	signaturesCmd.PersistentFlags().String("hash-algo", hashers.DefaultHasherName, "Hashing algorithm to use for signing and verification")
}
