// cloudflare-loadcheck is a bounded local or explicitly authorized remote validation CLI.
package main

import (
	"os"

	"github.com/Wei-Shaw/sub2api/internal/cloudflareloadcheck"
)

func main() {
	os.Exit(cloudflareloadcheck.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
