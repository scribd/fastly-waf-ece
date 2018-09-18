// Copyright © 2018 Scribd Inc. <ops@scribd.com>
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
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var address string
var ttl int
var debug bool
var logFile string
var maxLogSize int
var maxLogBackups int
var maxLogAge int
var logCompress bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fastly-waf-ece",
	Short: "Fastly WAF Event Correlation Engine",
	Long: `
Fastly WAF Event Correlation Engine

A service that receives syslog streams from Fastly WAF, and correlates them into (hopefully) useful event streams.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ece.yaml)")

	rootCmd.PersistentFlags().StringVarP(&address, "address", "a", "", "address to listen upon")
	rootCmd.PersistentFlags().IntVarP(&ttl, "ttl", "t", 20, "Time to wait for messages before flushing them downstream")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Debug.  Echos incoming logs to STEDERR")
	rootCmd.PersistentFlags().StringVarP(&logFile, "logFile", "l", "/var/log/fastly-waf-ece/events.log", "Log file path")
	rootCmd.PersistentFlags().IntVarP(&maxLogSize, "logSize", "s", 500, "max log file size")
	rootCmd.PersistentFlags().IntVarP(&maxLogBackups, "logBackups", "b", 5, "max log file backups")
	rootCmd.PersistentFlags().IntVarP(&maxLogAge, "logAge", "g", 28, "max log file age")
	rootCmd.PersistentFlags().BoolVarP(&logCompress, "logCompress", "c", false, "Compress logs")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".ece" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".ece")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
