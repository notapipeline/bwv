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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hokaccha/go-prettyjson"
	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
	"github.com/spf13/cobra"
)

var vaultItem types.VaultItem = types.VaultItem{}
var clientCmd types.ClientCmd = types.ClientCmd{}

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
		// Send to server
		var (
			req         *http.Request
			ctx         context.Context = context.Background()
			err         error
			address     string = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
			fields      string = "fields=" + strings.Join(vaultItem.Fields, ",")
			props       string = "properties=" + strings.Join(vaultItem.Parameters, ",")
			attachments string = "attachments=" + strings.Join(vaultItem.Attachments, ",")
		)

		if vaultItem.Path == "" {
			return fmt.Errorf("no path specified")
		}

		clientCmd.Token = getEncryptedToken()

		ctx = context.WithValue(ctx, transport.AuthToken{}, clientCmd.Token)
		var getProperties []string = make([]string, 0)
		if attachments != "attachments=" {
			getProperties = append(getProperties, attachments)
		}

		if fields != "fields=" {
			getProperties = append(getProperties, fields)
		}

		if props != "properties=" {
			getProperties = append(getProperties, props)
		}

		if vaultItem.Notes {
			getProperties = append(getProperties, "notes=true")
		}

		if vaultItem.SecureNotes {
			getProperties = append(getProperties, "securenotes=true")
		}

		var parameters string = strings.Join(getProperties, "&")

		if req, err = http.NewRequest("GET", address+"/"+vaultItem.Path+"?"+parameters, nil); err != nil {
			fatal("unable to create request for %s: %q", address, err)
			return nil
		}

		var r types.SecretResponse
		if err = transport.DefaultHttpClient.DoWithBackoff(ctx, req, &r); err != nil {
			log.Printf("%+v", clientCmd)
			fatal("unable to send request for %s: %q", address, err)
		}

		var b []byte
		if b, err = json.Marshal(r.Message); err != nil {
			return err
		}

		/*formatter := prettyjson.Formatter{
			//DisabledColor:   false,
			Indent:          4,
			Newline:         "\n",
			StringMaxLength: 0,
		}*/

		var structure interface{}
		if err = json.Unmarshal(b, &structure); err != nil {
			return err
		}

		if b, err = prettyjson.Marshal(structure); err != nil {
			return err
		}
		fmt.Println(string(b))
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
			case "-t", "--token", "-f", "--fields", "-p", "--params", "-a", "--attachments":
				fallthrough
			case "--config", "--server", "--port", "--cert", "--key":
				args = append(args, os.Args[i])
				args = append(args, os.Args[i+1])
				i += 2
			case "--skip-verify", "--debug", "--quiet":
				args = append(args, os.Args[i])
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
	// These are conistent across all commands
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/bwv/client.yaml)")
	rootCmd.PersistentFlags().StringVar(&clientCmd.Server, "server", "localhost", "address of the server")
	rootCmd.PersistentFlags().IntVar(&clientCmd.Port, "port", bitw.DefaultPort, "port of the server")
	rootCmd.PersistentFlags().BoolVar(&clientCmd.SkipVerify, "skip-verify", false, "skip verification of the server certificate")
	rootCmd.PersistentFlags().BoolVar(&clientCmd.Debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&clientCmd.Quiet, "quiet", false, "disable all logging")

	// these are for the client
	rootCmd.Flags().StringSliceVarP(&vaultItem.Fields, "fields", "f", []string{}, "Retrieve the field(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringSliceVarP(&vaultItem.Parameters, "params", "p", []string{}, "Retrieve the parameter(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringSliceVarP(&vaultItem.Attachments, "attachments", "a", []string{}, "Retrieve the attachment(s) from a vault item (may be specified multiple times)")
	rootCmd.Flags().StringVarP(&vaultItem.Path, "path", "P", "", "Path to the vault item")
	rootCmd.Flags().StringVarP(&clientCmd.Token, "token", "t", "", "Token for accessing the server")
}

func loadClientConfig() (err error) {
	c := config.New()
	if err = c.Load(config.ConfigModeClient); err != nil {
		return err
	}

	if clientCmd.Token == "" {
		clientCmd.Token = c.Token
		if c.Token == "" {
			fatal("no token specified")
		}
	}

	if clientCmd.Server == "" {
		clientCmd.Server = c.Address
		if c.Address == "" {
			clientCmd.Server = "localhost"
		}
	}

	if clientCmd.Port == 0 {
		clientCmd.Port = c.Port
		if c.Port == 0 {
			clientCmd.Port = bitw.DefaultPort
		}
	}

	return
}
