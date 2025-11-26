package main

import (
	"github.com/czh0526/aries-framework-go/cmd/aies-agent-rest/startcmd"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "aries-agent-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	logger := log.New("aries-agent-rest")

	startCmd, err := startcmd.Cmd(&startcmd.HTTPServer{})
	if err != nil {
		logger.Fatalf(err.Error())
	}

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run aries-agent-rest: %s", err)
	}
}
