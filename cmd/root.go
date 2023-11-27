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
	"os"

	"github.com/notapipeline/bwv/pkg/config"
	"github.com/spf13/cobra"
)

type VaultItem struct {
	Path       string
	Fields     []string
	Parameters []string
	Token      string
	Server     string
	Port       int
	Cert       string
	Key        string
	SkipVerify bool
}

var vaultItem VaultItem = VaultItem{}

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bwv",
	Short: "Bitwarden vault client",
	Long: `
Bitwarden vault client

This is a client for the Bitwarden vault. It can be used to retrieve secrets
from the vault and store them in the environment.

If called without any subcommands it will attempt to connect to a server running
on localhost:6277 and retrieve the secret at the specified path.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(os.Args[1:]) == 0 {
			return cmd.Help()
		}
		//log.SetOutput(io.Discard)
		if vaultItem.Token == "" {
			if err := loadClientConfig(); err != nil {
				return err
			}
		}

		if vaultItem.Path == "" {
			return fmt.Errorf("No path specified")
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SilenceErrors = true
	//rootCmd.SilenceUsage = true
	if c, err := rootCmd.ExecuteC(); err != nil {
		if rootCmd != c {
			return
		}

		// This is kinda ugly but we want to be able to ask for a path
		// without specifying the flag. So we'll try to map any unknown
		// single argument to the path flag and re-trigger the command.
		var args []string = make([]string, 0)
		args = append(args, os.Args[0])
		for i := 1; i < len(os.Args); {
			var f string = os.Args[i]
			switch f {
			case "-t", "--token":
				args = append(args, "-t")
				args = append(args, os.Args[i+1])
				i += 2
			case "-f", "--fields":
				args = append(args, "-f")
				args = append(args, os.Args[i+1])
				i += 2
			case "-p", "--params":
				args = append(args, "-p")
				args = append(args, os.Args[i+1])
				i += 2
			case "--config":
				args = append(args, "--config")
				args = append(args, os.Args[i+1])
				i += 2
			case "--server":
				args = append(args, "--server")
				args = append(args, os.Args[i+1])
				i += 2
			case "--port":
				args = append(args, "--port")
				args = append(args, os.Args[i+1])
				i += 2
			case "--cert":
				args = append(args, "--cert")
				args = append(args, os.Args[i+1])
				i += 2
			case "--key":
				args = append(args, "--key")
				args = append(args, os.Args[i+1])
				i += 2
			case "--skip-verify":
				args = append(args, "--skip-verify")
				i++
			default:
				args = append(args, "-P")
				args = append(args, f)
				i++
			}
		}
		os.Args = args
		rootCmd.SilenceUsage = true
		if err = rootCmd.Execute(); err != nil {
			fatal("Error: %s", err)
		}
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/bwv/client.yaml)")
	rootCmd.PersistentFlags().StringVar(&vaultItem.Server, "server", "", "address of the server (default is localhost)")
	rootCmd.PersistentFlags().IntVar(&vaultItem.Port, "port", 6277, "port of the server (default is 6277)")
	rootCmd.PersistentFlags().StringVar(&vaultItem.Cert, "cert", "", "path to the server certificate")
	rootCmd.PersistentFlags().StringVar(&vaultItem.Key, "key", "", "path to the server key")
	rootCmd.PersistentFlags().BoolVar(&vaultItem.SkipVerify, "skip-verify", false, "skip verification of the server certificate")

	rootCmd.Flags().StringSliceVarP(&vaultItem.Fields, "fields", "f", []string{}, "Retrieve the field(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringSliceVarP(&vaultItem.Parameters, "params", "p", []string{}, "Retrieve the parameter(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringVarP(&vaultItem.Path, "path", "P", "", "Path to the vault item")
	rootCmd.Flags().StringVarP(&vaultItem.Token, "token", "t", "", "Token for accessing the server")
}

func loadClientConfig() error {
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
