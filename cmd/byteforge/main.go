// Command byteforge is a binary transformation tool: it encodes, encrypts,
// renders, inspects, and verifies data. It never executes processed bytes.
package main

import (
	"os"

	"github.com/zoro/byteforge/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
