# Contributing

Run:

```
go run tools\lint\main.go
```

Or manually:

```
go fmt ./...
go vet ./...
```

It's a good idea to [install](https://golangci-lint.run/welcome/install/#local-installation) and run linter:

```
golangci-lint run ./...
```

Also you might run

```
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
```

Or make things stricter:

```
go install mvdan.cc/gofumpt@latest
gofumpt -l -w .
```