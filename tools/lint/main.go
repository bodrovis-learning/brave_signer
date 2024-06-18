package main

import (
	"fmt"
	"os"
	"os/exec"
)

func runCommand(cmd string, args []string) error {
	command := exec.Command(cmd, args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("error running %s %v: %v", cmd, args, err)
	}
	return nil
}

func main() {
	fmt.Println("Running go fmt...")
	if err := runCommand("go", []string{"fmt", "./..."}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Running go vet...")
	if err := runCommand("go", []string{"vet", "./..."}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Running custom linters...")
	if err := runCommand("golangci-lint", []string{"run", "./..."}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := runCommand("staticcheck", []string{"./..."}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := runCommand("gofumpt", []string{"-l", "-w", "."}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("All checks completed!")
}
