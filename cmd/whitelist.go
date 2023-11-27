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

	"github.com/spf13/cobra"
)

// whitelistCmd represents the whitelist command
var whitelistCmd = &cobra.Command{
	Use:   "whitelist",
	Short: "Handle whitelisted IP addresses",
	Long: `Whitelisted IP addresses help protect your secrets by denying access
	to the API from any IP address not on the whitelist. You can add or remove
	IP addresses from the whitelist using this command. You can also list the
	currently whitelisted IP addresses.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("whitelist called")
	},
}

var addCommand = &cobra.Command{
	Use:   "add",
	Short: "Add an IP address to the whitelist",
	Long: `Add an IP address to the whitelist. You can specify a single IP address
	or a CIDR block. If you specify a CIDR block, all addresses in the block
	will be added to the whitelist.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("add called")
	},
}

var removeCommand = &cobra.Command{
	Use:   "remove",
	Short: "Remove an IP address from the whitelist",
	Long: `Remove an IP address from the whitelist. You can specify a single IP address
	or a CIDR block. If you specify a CIDR block, all addresses in the block
	will be removed from the whitelist.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("remove called")
	},
}

var listCommand = &cobra.Command{
	Use:   "list",
	Short: "List the currently whitelisted IP addresses",
	Long: `List the currently whitelisted IP addresses. The list will be printed
	to stdout in CIDR notation, one address per line.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
	},
}

func init() {
	rootCmd.AddCommand(whitelistCmd)
	whitelistCmd.AddCommand(addCommand)
	whitelistCmd.AddCommand(removeCommand)
	whitelistCmd.AddCommand(listCommand)
}
