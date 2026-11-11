// Command cca is the continuous control assurance binary.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `cca: continuous control assurance

Usage:
  cca <command>

Commands:
  version   Print the build version

Not implemented yet: serve, collect, evaluate, export
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "serve", "collect", "evaluate", "export":
		fmt.Fprintf(stderr, "cca %s: not implemented\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "cca: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
