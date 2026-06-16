package main

import "github.com/cloudfoundry-community/safe/internal/cli"

// These are set at build time via -ldflags "-X main.<name>=...".
var (
	Version   string
	BuildTime string
	GitCommit string
)

func main() {
	cli.Main(Version, BuildTime, GitCommit)
}
