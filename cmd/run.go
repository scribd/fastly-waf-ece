// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/scribd/fastly-waf-ece/pkg/ece"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path"
	"time"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Runs the ECE",
	Long: `
Runs the ECE on the configured port.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if _, ok := os.Stat(logFile); os.IsNotExist(ok) {
			logDir := path.Base(logFile)
			err := os.MkdirAll(logDir, 0755)
			if err != nil {
				log.Fatalf("Could not create log dir %s: %s", logDir, err)
			}
		}

		if address == "" {
			log.Fatalln("Cannot run without a listen address (-a).  Run fastly-waf-ece help for more info.")
		}

		engine := ece.NewECE(time.Duration(ttl)*time.Second, logFile, maxLogSize, maxLogBackups, maxLogAge, logCompress, address)
		engine.Debug = debug

		err := engine.Start()
		if err != nil {
			log.Fatalf("failed to start server: %s", err)
		}

		engine.Wait()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
