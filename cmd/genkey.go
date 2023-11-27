//go:build !windows
// +build !windows

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
	"fmt"
	"log"
	"net/http"
	"net/mail"

	"github.com/spf13/cobra"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

var addresses []string

var fatal func(format string, v ...interface{}) = func(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// genkeyCmd represents the genkey command
var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate an API key",
	Long: `All calls to the API must be made with a known token. This command
	generates a new token and stores it encrypted in the server configuration
	file.

	During key generation, you will be prompted for your master password. This
	password is used to encrypt the API key before it is stored in the server
	but will not be sent to the server.

	You can generate a new key at any time. If you do, the old key will be
	discarded and you will need to update any scripts that use the old key.

	Each key is associated with a single IP address or CIDR block.

	You can generate a new token per block by specifying multiple blocks on the
	command line. For example:

	Generate a key for localhost:

		bwv genkey -e test@example.com

	Generate a specific key for system with address 192.168.0.2
	and a generic key for all hosts on 192.168.0.0/16 network

		bwv genkey -a 192.168.0.2 -a 192.168.0.0/16

	Specific keys (no block) take precedence over generic keys (block)

	The function will attempt to use GPG Pinentry if available, otherwise
	falls back to reading from stdin.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			password string
			err      error
			kdf      types.KDFInfo
		)
		for _, arg := range args {
			var found bool = false
			for _, address := range addresses {
				if address == arg {
					found = true
				}
			}
			if !found {
				addresses = append(addresses, arg)
			}
		}
		type message struct {
			Code    int    `json:"statuscode"`
			Message string `json:"message"`
		}

		if _, err = mail.ParseAddress(email); err != nil {
			fatal("invalid email address %q", err)
			return
		}

		if password, err = getPassword(); err != nil {
			fatal("invalid password %q", err)
			return
		}

		if len(addresses) == 0 {
			addresses = append(addresses, "localhost")
		}

		var ctx context.Context = context.Background()
		var localAddress string = fmt.Sprintf("https://%s:%d", vaultItem.Server, vaultItem.Port)
		if err = transport.DefaultHttpClient.Get(ctx, localAddress+"/api/v1/kdf", &kdf); err != nil {
			fatal("unable to get kdf info: %q", err)
			return
		}

		for _, address := range addresses {
			var token string
			if token = createToken(); token == "" {
				fatal("unable to create token for %s: %q", address, err)
				return
			}

			var encrypted string
			if encrypted, err = clientEncrypt(password, email, token, kdf); err != nil {
				fatal("unable to encrypt token: %q", err)
				return
			}
			// Send to server
			var (
				req *http.Request
				ctx context.Context = context.Background()
			)

			ctx = context.WithValue(ctx, transport.AuthToken{}, encrypted)
			if req, err = http.NewRequest("POST", localAddress+"/api/v1/storetoken", nil); err != nil {
				fatal("unable to create request for %s: %q", address, err)
				return
			}
			var r message
			if err = transport.DefaultHttpClient.DoWithBackoff(ctx, req, &r); err != nil {
				fatal("unable to send request for %s: %q", address, err)
			}

			if r.Code != 200 {
				fatal("Failed to store token: %s", r.Message)
				return
			}
			log.Printf("%s\t%s\n", address, token)
		}
	},
}

func init() {
	keyCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().StringSliceVarP(&addresses, "address", "a", []string{}, "IP address or CIDR block for this key")
	genkeyCmd.Flags().StringVarP(&email, "email", "e", "", "Email address for this key")
	if err := genkeyCmd.MarkFlagRequired("email"); err != nil {
		log.Fatal(err)
	}
}
