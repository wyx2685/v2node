package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "v0.5.0"
	codename = "v2node"
	intro    = "A V2board backend based on modified xray-core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

func showVersion() {
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}
