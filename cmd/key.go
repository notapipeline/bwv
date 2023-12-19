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

var addresses []net.IP

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key operations",
	Long: `The key command allows you to manage the API keys granted for use on
	this server. You can generate a new key, list the current keys, or revoke an
	existing key.

	The list key command will only work from the server console. It will not
	work from a remote client.`,
}

var genkeyCmd = &cobra.Command{
	Use:   "gen",
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
			err          error
			localAddress string = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
			response     types.SecretResponse
			ctx          context.Context = context.Background()
		)

		{
			clientCmd.Token = getEncryptedToken()
			ctx = context.WithValue(ctx, transport.AuthToken{}, clientCmd.Token)
		}

		adrs := make([]string, len(addresses))
		for _, address := range addresses {
			adrs = append(adrs, address.String())
		}

		err = transport.DefaultHttpClient.Post(ctx, localAddress+"/api/v1/storetoken", &response, adrs)
		if err != nil {
			fatal("unable to store token: %q", err)
			return
		}

		if err = printResponse(response); err != nil {
			fatal("Token has been stored but cannot be displayed: %q", err)
			return
		}
	},
}

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
	rootCmd.AddCommand(keyCmd)

	keyCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().IPSliceVarP(&addresses, "address", "a", []net.IP{}, "IP address or CIDR block for this key")

	keyCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().IPSliceVarP(&addresses, "addresses", "a", []net.IP{}, "IP addresses or CIDR blocks to revoke the token for")
}
