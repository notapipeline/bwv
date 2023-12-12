//go:build !windows

/*
 *   Copyright 2022 Martin Proffitt <mproffitt@choclab.net>
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

package unix

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/coreos/go-systemd/v22/dbus"
)

const SYSTEMFILE string = `
[Unit]
Description=Bitwarden HTTP API

[Service]
Environment="NO_DATELOG=true"
ExecStart=/usr/bin/bwv serve
ExecReload=/bin/kill -SIGINT "$MAINPID"
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`

var systemd *dbus.Conn

func init() {
	var err error
	if systemd, err = dbus.NewUserConnectionContext(context.Background()); err != nil {
		log.Fatal("Failed to initialise dbus connection.", err)
	}
}

func InstallService(serviceName string) error {
	home, _ := os.UserHomeDir()
	var (
		err         error
		service     string = fmt.Sprintf("%s.service", serviceName)
		servicePath string = filepath.Join(home, ".config/systemd/user", service)
		file        *os.File
	)

	log.Printf("Creating service file %s\n", servicePath)
	if file, err = os.Create(servicePath); err != nil {
		return fmt.Errorf("Unable to create service file: %v", err)
	}

	if _, err = file.WriteString(SYSTEMFILE); err != nil {
		return fmt.Errorf("Unable to write service file: %v", err)
	}

	if err = file.Sync(); err != nil {
		return fmt.Errorf("Unable to sync service file: %v", err)
	}
	file.Close()

	log.Printf("Enabling systemd user service '%s' and reloading daemon\n", serviceName)
	var files []string = []string{service}
	{
		_, _, err = systemd.EnableUnitFilesContext(context.Background(), files, false, true)
		if err != nil {
			return fmt.Errorf("Failed to enable the %s service: %v", serviceName, err)
		}
	}

	if err = systemd.ReloadContext(context.Background()); err != nil {
		return fmt.Errorf("Failed to reload the Daemon: %v", err)
	}

	return nil
}

func RemoveService(serviceName string) error {
	home, _ := os.UserHomeDir()
	var (
		err         error
		channel     chan string = make(chan string)
		service     string      = fmt.Sprintf("%s.service", serviceName)
		servicePath string      = filepath.Join(home, ".config/systemd/user", service)
	)
	_, err = systemd.StopUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to stop %s service: %v", serviceName, err)
	}
	log.Println(<-channel)

	var files []string = []string{service}
	_, err = systemd.DisableUnitFilesContext(context.Background(), files, false)
	if err != nil {
		return fmt.Errorf("Failed to disable the %s service: %v", serviceName, err)
	}

	if err = systemd.ReloadContext(context.Background()); err != nil {
		return fmt.Errorf("Failed to reload the Daemon: %v", err)
	}
	if err = os.Remove(servicePath); err != nil {
		return fmt.Errorf("Unable to delete service file at %s. %v", servicePath, err)
	}
	return nil
}
