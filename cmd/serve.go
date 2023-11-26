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
	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/spf13/cobra"
)

type Serve struct {
	Whitelist  []string
	APIKeys    []string
	Cert       string
	Key        string
	Port       int
	Org        string
	Collection string
	Debug      bool
	Quiet      bool
}

var serve Serve = Serve{}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Runs a local server hosting secrets from Bitwarden",
	Long: `The serve command connects to Bitwarden and retrieves the encrypted
	secret store. It then starts a local server that can be used to retrieve
	secrets from the store and send them back in cleartext.

	The server can be configured to only respond to requests from a whitelist
	of IP addresses. The whitelist can be specified as a comma-separated list
	of IP addresses or CIDR blocks using the --whitelist flag. If no whitelist
	is specified, the server will respond to all requests.

	The server can be configured to require an API key for each request. The
	key is specified as a comma-separated list of hostnames and keys using the
	--api-keys flag. If no API keys are specified, the server will respond to
	all requests.

	The server can be configured to use TLS. The certificate and key are
	specified using the --cert and --key flags. If no certificate or key is
	specified, the server will use HTTP instead of HTTPS.

	The server can be configured to listen on a specific port using the --port
	flag. If no port is specified, the server will listen on port 6277.

	The server can be configured to use a specific Bitwarden organization using
	the --org flag. If no organization is specified, the server will use the
	default organization.

	The server can be configured to use a specific Bitwarden collection using
	the --collection flag. If no collection is specified, the server will use
	the default collection.

	If no flags are specified, the server will look for a configuration file
	at ~/.config/bwv/config.json. If the file exists at this location, it will
	be created with default values.`,

	Run: func(cmd *cobra.Command, args []string) {
		server := bitw.NewHttpServer()
		server.ListenAndServe()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringSliceVarP(&serve.Whitelist, "whitelist", "w", []string{}, "Comma-separated list of IP addresses or CIDR blocks to whitelist")
	serveCmd.Flags().StringSliceVarP(&serve.APIKeys, "api-keys", "k", []string{}, "Comma-separated list of hostnames and API keys to require")
	serveCmd.Flags().StringVarP(&serve.Cert, "cert", "c", "", "Path to TLS certificate")
	serveCmd.Flags().StringVarP(&serve.Key, "key", "K", "", "Path to TLS key")
	serveCmd.Flags().IntVarP(&serve.Port, "port", "p", 6277, "Port to listen on")
	serveCmd.Flags().StringVarP(&serve.Org, "org", "o", "", "Bitwarden organization to use")
	serveCmd.Flags().StringVarP(&serve.Collection, "collection", "C", "", "Bitwarden collection to use")
	serveCmd.Flags().BoolVarP(&serve.Debug, "debug", "d", false, "Enable debug logging")
	serveCmd.Flags().BoolVarP(&serve.Quiet, "quiet", "q", false, "Disable all logging")
}
