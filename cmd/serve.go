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
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/types"
	"github.com/notapipeline/bwv/pkg/unix"
	"github.com/spf13/cobra"
)

var (
	serve types.ServeCmd = types.ServeCmd{}
	cnf   *config.Config
)

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
	at ~/.config/bwv/server.yaml. If no file exists at this location, it will
	be created with default values or using values from the environment.

	If --autoload is specified, the server will automatically load all items
	marked with a field "autoload". This is useful for loading secrets into
	the environment when the server starts or for preloading SSH keys into
	the ssh-agent.

	To use the autoload facility, add a field "autoload" to the secret in the
	vault. The value of this field should be "true" to load all attachments for
	the given secret, or a comma-separated list of attachment names to load.

	For example, to load all attachments for a secret, add a field "autoload"
	with the value "true". To load only the attachments "id_rsa" and "id_rsa.pub",
	add a field "autoload" with the value "id_rsa,id_rsa.pub".

	To load a password-protected attachment, add a custom field with the name
	of the attachment and the password as the value. For example, to load a
	secret key with the password "password", add a field "id_rsa" with the
	value "password".

	It is possible to create environment configuration files for each secret
	in the vault. This is achieved by adding a field "environment" to the
	secret. The value of this field should be a comma-separated list of
	fields and properties to load. For example, to be able to load the username
	and password properties, as well as a hidden field "token" then the
	"environment" field should be set to "username,password,token". This will
	create an environment file at ~/.config/bwv/environment/<secret-name>.env
	with the contents:

	  export CIPHER_NAME_USERNAME=<username>
	  export CIPHER_NAME_PASSWORD=<password>
	  export CIPHER_NAME_TOKEN=<token>

	Note: These files will not be automatically loaded into the environment but
	can be sourced using the script:

	  for file in $(ls ~/.config/bwv/environment/*.env); do source $file; done

	This should be added to your shell profile to ensure that the environment
	files are loaded when you start a new shell.

	The environment files will be refreshed from the vault once an hour, or
	when the server receives a SIGHUP signal.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		cnf = config.New()
		serve.Merge(&clientCmd)
		var (
			autoload   chan bool
			done       chan bool        = make(chan bool)
			signals    chan os.Signal   = make(chan os.Signal, 1)
			server     *bitw.HttpServer = bitw.NewHttpServer(cnf)
			autoloader *unix.Autoloader
		)

		if serve.Autoload {
			autoload = make(chan bool)
			autoloader = unix.NewAutoloader(server.Bwv)
		}

		signal.Notify(signals, syscall.SIGHUP)
		go func() {
			for {
				s := <-signals
				switch s {
				case syscall.SIGHUP:
					log.Println("received SIGHUP, reloading environment files")
					autoload <- true
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
					done <- true
				}
			}
		}()

		go func() {
			for {
				select {
				case <-autoload:
					if serve.Autoload {
						if err := autoloader.AutoLoad(server.Bwv); err != nil {
							log.Printf("failed to autoload: %q", err)
						}
					}
				case <-done:
					return
				}
			}
		}()

		if err := server.ListenAndServe(&serve, &autoload); err != nil {
			fatal("failed to start server %q", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringToStringVarP(&serve.ApiKeys, "api-keys", "k", map[string]string{}, "Comma-separated list of `hostname=token` to require")

	serveCmd.Flags().StringVarP(&serve.Cert, "cert", "C", "", "Path to TLS certificate")
	serveCmd.Flags().StringVarP(&serve.Key, "key", "K", "", "Path to TLS key")

	serveCmd.Flags().StringVarP(&serve.Org, "org", "o", "", "Bitwarden organization to use")
	serveCmd.Flags().StringVarP(&serve.Collection, "collection", "c", "", "Bitwarden collection to use")
	serveCmd.Flags().BoolVarP(&serve.Autoload, "autoload", "A", false, "Autoload elements from the vault")
}
