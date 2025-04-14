package config

import (
	"fmt"
	"strings"

	"brave_signer/internal/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GlobalConfig defines the shared configuration options.
type GlobalConfig struct {
	ConfigFileName string `mapstructure:"config-file-name"`
	ConfigFileType string `mapstructure:"config-file-type"`
	ConfigPath     string `mapstructure:"config-path"`
}

// Conf holds the Viper instance after loading the config.
var Conf *viper.Viper

// GlobalCfg is the parsed, typed global configuration.
var GlobalCfg GlobalConfig

// LoadConfig loads configuration from the CLI flags and an optional YAML file.
// CLI args take precedence over file settings.
func LoadConfig(cmd *cobra.Command) error {
	v := viper.New()

	// Allow ENV vars like BRAVE_SIGNER_CONFIG_PATH
	v.SetEnvPrefix("BRAVE_SIGNER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	rootCmd := cmd.Root()
	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		return fmt.Errorf("failed to bind root persistent flags: %w", err)
	}

	configFileName := v.GetString("config-file-name")
	configFileType := v.GetString("config-file-type")
	configPath := v.GetString("config-path")

	v.SetConfigName(configFileName)
	v.SetConfigType(configFileType)
	v.AddConfigPath(configPath)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Info("Config file not found, using CLI values and defaults.")
		} else {
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	if err := v.Unmarshal(&GlobalCfg); err != nil {
		return fmt.Errorf("failed to unmarshal global config: %w", err)
	}

	Conf = v

	return nil
}
