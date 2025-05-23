## brave_signer completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(brave_signer completion zsh)

To load completions for every new session, execute once:

#### Linux:

	brave_signer completion zsh > "${fpath[1]}/_brave_signer"

#### macOS:

	brave_signer completion zsh > $(brew --prefix)/share/zsh/site-functions/_brave_signer

You will need to start a new shell for this setup to take effect.


```
brave_signer completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config-file-name string   Your config file name. (default "config")
      --config-file-type string   Your config file type. (default "yaml")
      --config-path string        Config file location. (default ".")
```

### SEE ALSO

* [brave_signer completion](brave_signer_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 29-Apr-2025
