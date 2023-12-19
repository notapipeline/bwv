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
	"os"
	"path/filepath"

	"github.com/notapipeline/bwv/pkg/unix"
	"github.com/spf13/cobra"
)

var appName string

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "manages the systemd service running the bwv server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("service called")
	},
}

var startCommand = &cobra.Command{
	Use:   "start",
	Short: "Starts the service",
	Long:  `Starts the bwv service`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := unix.StartService(appName); err != nil {
			log.Fatal(err)
		}
	},
}

var stopCommand = &cobra.Command{
	Use:   "stop",
	Short: "Stops the service",
	Long:  `Stops the bwv service`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := unix.StopService(appName); err != nil {
			log.Fatal(err)
		}
	},
}

var restartCommand = &cobra.Command{
	Use:   "restart",
	Short: "Restart the service",
	Long:  `Restart the service`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := unix.StopService(appName); err != nil {
			log.Fatal(err)
		}
		if err := unix.StartService(appName); err != nil {
			log.Fatal(err)
		}
	},
}

var statusCommand = &cobra.Command{
	Use:   "status",
	Short: "Status of the service",
	Long:  `Status of the service`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			status string
			err    error
		)
		if status, err = unix.ServiceStatus(appName); err != nil {
			log.Fatal(err)
		}
		fmt.Println(status)
	},
}

var installServiceCommand = &cobra.Command{
	Use:   "install",
	Short: "Install the service",
	Long:  `Install the service`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := unix.InstallService(appName); err != nil {
			log.Fatal(err)
		}
	},
}

var removeServiceCommand = &cobra.Command{
	Use:   "remove",
	Short: "Remove the service",
	Long:  `Remove the service`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := unix.RemoveService(appName); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	appName = filepath.Base(os.Args[0])
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(startCommand)
	serviceCmd.AddCommand(stopCommand)
	serviceCmd.AddCommand(restartCommand)
	serviceCmd.AddCommand(statusCommand)
	serviceCmd.AddCommand(installServiceCommand)
	serviceCmd.AddCommand(removeServiceCommand)
}
