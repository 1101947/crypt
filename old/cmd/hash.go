package cmd

import (
	//"fmt"

	//"github.com/spf13/cobra"
)
//
//var (
//	Function string
//	Data string
//	DatAt string
//)
//
//func init() {
//	hashCmd.Flags().StringVarP(&Data, "data", "", "", "data to hash")
//	hashCmd.Flags().StringVarP(&DatAt, "data_at", "", "", "data at path to hash")
//	hashCmd.MarkFlagsMutuallyExclusive("data", "data_at")
//	hashCmd.Flags().StringVarP(&Out, "out", "", "", "file to output")
//	hashCmd.Flags().StringVarP(&Function, "function", "", "", "Hash function to use")
//	rootCmd.AddCommand(hashCmd)
//}
//
//var hashCmd = &cobra.Command{
//	Use: "hash",
//	Short: "Hashes value",
//	Long: "TODO",
//	Run: func(cmd *cobra.Command, args []string) {
//		fmt.Println("hi")
//	},
//}
//
//// takes data to hash from stdin(by default) hashes and writes hash to stdout(by default, or, if specified, to file(see --out flag))
//// crypt hash --data=stdin --password=stdin
//// data:
////	stdin
////	FILE=file
////	ask
//// password:
////	stdin
////	FILE=file
////	ask
//// function
