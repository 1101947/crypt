package cmd 

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "crypt",
	Short: "Crypt is an plane simple encryption tool",
	Long: `A plane simple crossplatform encryption tool, 
	NOTE: crypt is unstable, please, DONT USE IN PRODUCTION`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Help!")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}


