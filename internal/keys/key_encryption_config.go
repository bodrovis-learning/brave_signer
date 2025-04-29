package keys

import (
	"brave_signer/internal/config"
)

type KeyEncryptionConfig struct {
	SaltSize      int    `mapstructure:"salt-size"`
	Argon2Time    uint32 `mapstructure:"argon2-time"`
	Argon2Memory  uint32 `mapstructure:"argon2-memory"`
	Argon2Threads uint8  `mapstructure:"argon2-threads"`
	Argon2KeyLen  uint32 `mapstructure:"argon2-key-len"`
}

func BuildCryptoConfigFromFlags() KeyEncryptionConfig {
	return KeyEncryptionConfig{
		SaltSize:      config.Conf.GetInt("crypto.salt-size"),
		Argon2Time:    config.Conf.GetUint32("crypto.argon2-time"),
		Argon2Memory:  config.Conf.GetUint32("crypto.argon2-memory"),
		Argon2Threads: config.Conf.GetUint8("crypto.argon2-threads"),
		Argon2KeyLen:  config.Conf.GetUint32("crypto.argon2-key-len"),
	}
}
