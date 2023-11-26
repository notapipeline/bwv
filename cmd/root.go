/*
 *   Copyright 2023 Martin Proffitt <mproffitt@choclab.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package cmd

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/notapipeline/bwv/pkg/config"
	"github.com/spf13/cobra"
)

type VaultItem struct {
	Path       string
	Fields     []string
	Parameters []string
	Token      string
}

var vaultItem VaultItem = VaultItem{}

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bwv",
	Short: "Bitwarden vault client",
	Long: `Bitwarden vault client

	This is a client for the Bitwarden vault. It can be used to retrieve secrets
	from the vault and store them in the environment.

	If called without any subcommands it will attempt to connect to a server
	running on localhost:6277 and retrieve the secret at the specified path.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		log.SetOutput(io.Discard)
		if vaultItem.Path == "" {
			if err := cmd.Help(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if vaultItem.Token == "" {
				if err := loadClientConfig(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
			return
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SilenceErrors = true
	if _, err := rootCmd.ExecuteC(); err != nil {
		// If we receive an error here, try mapping the first argument to the
		// path flag and re-triggering the command. If that still doesn't work,
		// bail out.
		var args []string = make([]string, 0)
		args = append(args, os.Args[0])
		args = append(args, "-P")
		args = append(args, os.Args[1:]...)
		os.Args = args
		rootCmd.SilenceErrors = false
		if err = rootCmd.Execute(); err != nil {
			fmt.Println(err)
			if err = rootCmd.Help(); err != nil {
				fmt.Println(err)
			}
			os.Exit(1)
		}
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/bwv/client.yaml)")

	rootCmd.Flags().StringSliceVarP(&vaultItem.Fields, "fields", "f", []string{}, "Retrieve the field(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringSliceVarP(&vaultItem.Parameters, "params", "p", []string{}, "Retrieve the parameter(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringVarP(&vaultItem.Path, "path", "P", "", "Path to the vault item")
	rootCmd.Flags().StringVarP(&vaultItem.Token, "token", "t", "", "Token for accessing the server")
}

func loadClientConfig() error {
	if _, err := os.Stat(os.Getenv("HOME") + "/.config/bwv/client.yaml"); err != nil {
		return fmt.Errorf("No client configuration found")
	}
	c := config.New()
	if err := c.Load(config.ConfigModeClient); err != nil {
		return err
	}
	if c.Token == "" {
		return fmt.Errorf("No token found in client configuration")
	}
	vaultItem.Token = c.Token
	return nil
}
