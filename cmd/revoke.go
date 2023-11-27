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
	"log"
	"net/http"
	"net/mail"

	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
	"github.com/spf13/cobra"
)

var (
	address string
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke the token for a given address or cidr block",
	Long: `This command will revoke the token for a given address or cidr block.
You must specify either an address or a cidr block. You cannot specify both.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			password string
			err      error
			token    string
			kdf      types.KDFInfo
			req      *http.Request
			ctx      context.Context = context.Background()
		)

		if _, err = mail.ParseAddress(email); err != nil {
			fatal("invalid email address %q", err)
			return
		}

		if password, err = getPassword(); err != nil {
			fatal("invalid password %q", err)
		}

		// TODO: localhost address and port are hardcoded - move to config
		if err = transport.DefaultHttpClient.Get(ctx, "https://localhost:6278/api/v1/kdf", &kdf); err != nil {
			fatal("unable to get kdf info: %q", err)
		}

		if token, err = crypto.ClientEncrypt(password, email, address, kdf); err != nil {
			fatal("unable to encrypt token: %q", err)
		}

		// Send to server
		ctx = context.WithValue(ctx, transport.AuthToken{}, token)
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
	},
}

func init() {
	keyCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().StringVarP(&address, "address", "a", "", "IP address or CIDR block to revoke the token for")
	revokeCmd.Flags().StringVarP(&email, "email", "e", "", "Email address for this key")
	if err := genkeyCmd.MarkFlagRequired("email"); err != nil {
		log.Fatal(err)
	}
}
