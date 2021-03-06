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
//go:build !windows
package unix

import (
	"context"
	"fmt"
	"log"

	"github.com/coreos/go-systemd/v22/dbus"
)

func StartService(serviceName string) error {
	var (
		channel chan string = make(chan string)
		service string      = fmt.Sprintf("%s.service", serviceName)
		err     error
	)
	log.Printf("Starting %s service\n", serviceName)
	_, err = systemd.StartUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to start %s service: %v", serviceName, err)
	}

	log.Println(<-channel)
	return nil
}

func StopService(serviceName string) error {
	var (
		channel chan string = make(chan string)
		service string      = fmt.Sprintf("%s.service", serviceName)
		err     error
	)
	log.Printf("Stopping %s service\n", serviceName)
	_, err = systemd.StopUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to start %s service: %v", serviceName, err)
	}
	log.Println(<-channel)
	return nil
}

func ServiceStatus(serviceName string) (*dbus.UnitStatus, error) {
	var (
		err      error
		service  string = fmt.Sprintf("%s.service", serviceName)
		statuses []dbus.UnitStatus
	)

	if statuses, err = systemd.ListUnitsByNames([]string{service}); err != nil {
		return nil, fmt.Errorf("Failed to get service status for %s", serviceName)
	}
	return &statuses[0], nil
}
