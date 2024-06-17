package config

import (
	"fmt"

	"brave_signer/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// LoadYamlConfig loads and binds configuration from a YAML file
func LoadYamlConfig(cmd *cobra.Command) error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Info("Config file not found; using default values.")
			return nil // Returning nil because the absence of a config file might be acceptable.
		} else {
			return fmt.Errorf("found config file, but encountered an error: %v", err)
		}
	}
	return nil
}

// BindFlags binds Cobra flags to Viper configuration
func BindFlags(cmd *cobra.Command) error {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if err := viper.BindPFlag(flag.Name, flag); err != nil {
			logger.Warn(fmt.Errorf("error binding flag '%s': %v", flag.Name, err))
		}
	})

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if !flag.Changed && viper.IsSet(flag.Name) {
			if err := cmd.Flags().Set(flag.Name, viper.GetString(flag.Name)); err != nil {
				logger.Warn(fmt.Errorf("error setting flag '%s' from config: %v", flag.Name, err))
			}
		}
	})
	return nil
}
