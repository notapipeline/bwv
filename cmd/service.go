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
	"log"

	"github.com/spf13/cobra"
)

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("service called")
	},
}

var startCommand = &cobra.Command{
	Use:   "start",
	Short: "Starts the service",
	Long:  `Starts the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting service")
	},
}

var stopCommand = &cobra.Command{
	Use:   "stop",
	Short: "Stops the service",
	Long:  `Stops the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Stopping service")
	},
}

var restartCommand = &cobra.Command{
	Use:   "restart",
	Short: "Restart the service",
	Long:  `Restart the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Restart service")
	},
}

var statusCommand = &cobra.Command{
	Use:   "status",
	Short: "Status of the service",
	Long:  `Status of the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Status of service")
	},
}

var installCommand = &cobra.Command{
	Use:   "install",
	Short: "Install the service",
	Long:  `Install the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Install service")
	},
}

var removeCommand = &cobra.Command{
	Use:   "remove",
	Short: "Remove the service",
	Long:  `Remove the service`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Remove service")
	},
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(startCommand)
	serviceCmd.AddCommand(stopCommand)
	serviceCmd.AddCommand(restartCommand)
	serviceCmd.AddCommand(statusCommand)
	serviceCmd.AddCommand(installCommand)
	serviceCmd.AddCommand(removeCommand)
}
