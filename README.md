# BraveSigner

> Bravely generate key pairs, sign files, and check signatures.

This program, written in Go, contains a collection of tools to generate key pairs in PEM files, sign files, and verify signatures.

**[Find MD documentation in the /docs folder](./docs/brave_signer.md)**

## Usage

Run it:

```
brave_signer COMMAND FLAGS
```

Available commands (check documentation to learn about all supported settings):

* `keys generate [--pub-key-path pub_key.pem] [--priv-key-path priv_key.pem]` — generate an RSA key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with Argon2 key derivation function is utilized.
* `signatures signfile --file PATH_TO_FILE --signer-id SIGNER_NAME_OR_ID [--priv-key priv_key.pem]` — sign the specified file using an RSA private key (you'll be asked for a passphrase to decrypt the private key) and store the signature inside a .sig file named after the original file. The signature will also contain the signer's name or ID. This ID may take any form, and currently it's limited to 65535 characters.
* `signatures verifyfile --file PATH_TO_FILE [--pub-key pub_key.pem]` — verify the digital signature of a specified file using an RSA public key and the signature file. The signature file should have the same basename as the actual file and be stored in the same directory.

### Config

All command line arguments can also be specified inside a config file. By default the script searches for a `config.yaml` file inside the current directory but it can be adjusted with the following CLI arguments:

* `--config-file-name` (defaults to `config`)
* `--config-file-type` (defaults to `yaml`)
* `--config-path` (defaults to `.`)

For example, to adjust the signer:

```yaml
signer-id: John Doe
```

In this case, you don't need to provide `--signer-id` when calling `signatures signfile`.

Note that CLI flags have priority over the parameters provided in the config file.

## License

(c) [Ilya Krukowski](https://bodrovis.tech)
