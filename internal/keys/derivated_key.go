package keys

import (
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"

	"golang.org/x/term"
)

func DeriveKey(cryptoConfig KeyEncryptionConfig, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	passphrase, err := getPassphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch passphrase: %v", err)
	}

	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	return argon2.IDKey(passphrase, salt, cryptoConfig.Argon2Time, cryptoConfig.Argon2Memory*1024, cryptoConfig.Argon2Threads, cryptoConfig.Argon2KeyLen), nil
}

func getPassphrase() (passphrase []byte, err error) {
	fmt.Println("Enter passphrase:")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to set terminal to raw mode: %v", err)
	}
	defer func() {
		if restoreErr := safeRestore(int(os.Stdin.Fd()), oldState); restoreErr != nil {
			err = fmt.Errorf("failed to restore terminal: %v", restoreErr)
		}
	}()

	passphrase, err = term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %v", err)
	}

	return passphrase, nil
}

// safeRestore attempts to restore the terminal to its original state and logs an error if it fails.
func safeRestore(fd int, state *term.State) error {
	if err := term.Restore(fd, state); err != nil {
		return fmt.Errorf("safe restoration error: %v", err)
	}

	return nil
}
