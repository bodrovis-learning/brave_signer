# BraveSigner

> Bravely generate key pairs, sign files, and check signatures.

BraveSigner is a Go-powered CLI tool that lets you generate cryptographic key pairs, sign files, and verify digital signatures using [Ed25519](https://ed25519.cr.yp.to/). It prioritizes strong encryption practices, ease of use, and flexibility.

**[Full command reference in `/docs/brave_signer.md`](./docs/brave_signer.md)**

---

## Usage

```
brave_signer COMMAND FLAGS
```

Available commands:

- `keys generate [--pub-key-path pub_key.pem] [--priv-key-path priv_key.pem]`  
  Generate an Ed25519 key pair.  
  The private key is encrypted with AES using a passphrase you enter, derived securely via Argon2.

- `signatures signfile --file PATH_TO_FILE --signer-id SIGNER_NAME_OR_ID [--priv-key-path priv_key.pem]`  
  Sign a file using your private key.  
  A `.sig` file will be created next to the original file, containing the signature and signer ID (up to 65,535 characters).

- `signatures verifyfile --file PATH_TO_FILE [--pub-key-path pub_key.pem]`  
  Verify a file against its `.sig` using an Ed25519 public key.  
  The `.sig` file should be named `<filename>.sig` and stored alongside the original.

---

## Configuration

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

### Environment variables

All parameters can also be provided via environment variables. This is useful in CI/CD setups, containerized environments, or when you want to avoid hardcoding values in config files.

Environment variables follow this format:

```
BRAVE_SIGNER_<PARAMETER_NAME>
```

Hyphens (-) in parameter names are replaced with underscores (_). For example `--file-path` can be set with `BRAVE_SIGNER_FILE_PATH`.

### Precedence order

When resolving configuration values, the priority is as follows:

1. Command-line arguments
2. Environment variables
3. Config file (config.yaml, etc.)
4. Default values

## License

(c) [Ilya Krukowski](https://bodrovis.tech)
