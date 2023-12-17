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
	"net"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
	"github.com/spf13/cobra"
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke the token for a given address or cidr block",
	Long: `This command will revoke the token for a given address or cidr block.
You must specify either an address or a cidr block. You cannot specify both.`,
	Run: func(cmd *cobra.Command, args []string) {

		var (
			ok           bool
			r            map[string]any
			err          error
			response     types.SecretResponse
			localAddress string          = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
			ctx          context.Context = context.Background()
		)
		{
			clientCmd.Token = getEncryptedToken()
			ctx = context.WithValue(ctx, transport.AuthToken{}, clientCmd.Token)
		}

		err = transport.DefaultHttpClient.Post(ctx, localAddress+"/api/v1/storetoken", &response, addresses)
		if err != nil {
			fatal("unable to store token: %q", err)
			return
		}

		if r, ok = response.Message.(map[string]any); !ok {
			fatal("unexpected response from server: %q", response.Message)
			return
		}

		if _, ok = r["revoked"]; ok {
			for _, address := range r["revoked"].([]any) {
				log.Printf("Token revoked for address %s", address.(string))
			}
		}

		if _, ok = r["failed"]; ok {
			for _, address := range r["failed"].([]any) {
				log.Printf("Token not revoked for address %s", address.(string))
			}
		}
	},
}

func init() {
	keyCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().IPSliceVarP(&addresses, "addresses", "a", []net.IP{}, "IP addresses or CIDR blocks to revoke the token for")
}
