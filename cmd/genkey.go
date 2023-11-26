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
	"strings"

	"github.com/spf13/cobra"
	"github.com/twpayne/go-pinentry"

	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

var addresses []string
var email string

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
			kdf      types.KDFInfo = types.KDFInfo{
				Type:       types.KDFTypePBKDF2,
				Iterations: 1,
			}
			key, mac []byte
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

		if _, err = mail.ParseAddress(email); err != nil {
			fatal("invalid email address %q", err)
			return
		}

		if password, err = getPassword(); err != nil {
			fatal("invalid password %q", err)
		}

		if len(addresses) == 0 {
			addresses = append(addresses, "localhost")
		}

		if key, mac, err = crypto.DeriveStretchedMasterKey([]byte(password), email, kdf); err != nil {
			fatal("unable to stretch master password: %v", err)
		}

		for _, address := range addresses {
			var token string
			if token = config.CreateToken(); token == "" {
				fatal("unable to create token for %s: %q", address, err)
			}

			var t types.CipherString
			{
				if t, err = crypto.EncryptWith([]byte(token), types.AesCbc256_HmacSha256_B64, key, mac); err != nil {
					fatal("unable to encrypt token for %s: %q", address, err)
				}
			}

			// Send to server
			var (
				req *http.Request
				ctx context.Context = context.Background()
			)

			ctx = context.WithValue(ctx, transport.AuthToken{}, t.String())
			if req, err = http.NewRequest("POST", "https://localhost:6278/api/v1/storetoken", nil); err != nil {
				fatal("unable to create request for %s: %q", address, err)
			}
			var r struct {
				Code    int    `json:"statuscode"`
				Message string `json:"message"`
			} = struct {
				Code    int    `json:"statuscode"`
				Message string `json:"message"`
			}{}
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
	rootCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().StringSliceVarP(&addresses, "address", "a", []string{}, "IP address or CIDR block for this key")
	genkeyCmd.Flags().StringVarP(&email, "email", "e", "", "Email address for this key")
	if err := genkeyCmd.MarkFlagRequired("email"); err != nil {
		log.Fatal(err)
	}
}

var getPassword func() (string, error) = func() (string, error) {
	return func() (string, error) {
		var (
			err         error
			client      *pinentry.Client
			password    string
			usePinentry bool = true
		)

		if client, err = getPinentry(
			pinentry.WithBinaryNameFromGnuPGAgentConf(),
			pinentry.WithDesc("Please enter your Bitwarden master password."),
			pinentry.WithGPGTTY(),
			pinentry.WithPrompt("Password:"),
			pinentry.WithTitle("Master password"),
		); err != nil {
			if password, err = readPassword("Please enter your Bitwarden master password: "); err != nil {
				return "", err
			}
			usePinentry = false
		}

		if usePinentry {
			defer client.Close()
			password, _, err = client.GetPIN()
			if pinentry.IsCancelled(err) {
				return "", fmt.Errorf("Cancelled")
			}
		}
		if password == "" {
			return "", fmt.Errorf("No password provided")
		}
		password = strings.TrimSpace(password)
		return password, err
	}()
}

var getPinentry func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) = func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
	return pinentry.NewClient(options...)
}

var readPassword func(prompt string) (string, error) = func(prompt string) (string, error) {
	return bitw.ReadPassword(prompt)
}
