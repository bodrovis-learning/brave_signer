# BraveSigner

> Bravely generate key pairs, sign files, and check signatures.

This program, written in Go, contains a collection of tools to generate key pairs in PEM files, sign files, and verify signatures.

## Usage

Run it:

```bash
brave_signer COMMAND FLAGS
```

Available commands:

* `keys generate [--pub-out pub_key.pem] [--priv-out priv_key.pem]` — generate an RSA key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with Argon2 key derivation function is utilized.
* `signatures signfile --file PATH_TO_FILE --signer-id SIGNER_NAME_OR_ID [--priv-key priv_key.pem]` — sign the specified file using an RSA private key (you'll be asked for a passphrase to decrypt the private key) and store the signature inside a .sig file named after the original file. The signature will also contain the signer's name or ID. This ID may take any form, and currently it's limited to 65535 characters.
* `signatures verifyfile --file PATH_TO_FILE [--pub-key pub_key.pem]` — verify the digital signature of a specified file using an RSA public key and the signature file. The signature file should have the same basename as the actual file and be stored in the same directory.

## License

(c) [Ilya Krukowski](https://bodrovis.tech)