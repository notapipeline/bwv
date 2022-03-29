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
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"

	"github.com/hokaccha/go-prettyjson"
	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/unix"
)

var (
	loginResponse *bitw.LoginResponse
	authToken     string
	appName       string = "bwv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage bwv [ serve [ --whitelist 127.0.0.1,192.168.1.1,...] <path>")
		return
	}

	var (
		path string
		c    interface{}
		s    server = server{}
		err  error
	)

	path = os.Args[1]
	switch path {
	case "serve":
		s.listenAndServe()
	case "install":
		if err = unix.InstallService(appName); err == nil {
			unix.StartService(appName)
		}
	case "remove":
		err = unix.RemoveService(appName)
	case "start":
		err = unix.StartService(appName)
	case "stop":
		err = unix.StopService(appName)
	case "status":
		var status *dbus.UnitStatus
		status, err = unix.ServiceStatus(appName)
		if err == nil {
			fmt.Println(status.SubState)
		}
	case "genkey":
		if len(os.Args) < 3 {
			fmt.Println("Please specify an IP or CIDR range for this key")
			return
		}

		if len(strings.Split(os.Args[2], ",")) != 1 {
			fmt.Println("Only a single IP or CIDR range should be provided")
			return
		}
		if err = parseWhitelist(&s, os.Args[2], false); err != nil {
			fmt.Println(err.Error())
			return
		}
		s.AddApiKey(os.Args[2])
	case "revoke":
		s.load()
		if len(os.Args) < 3 {
			fmt.Println("Please specify the api key or ip/range to revoke")
			return
		}
		s.RevokeApiKey(os.Args[2])
	case "whitelist":
		if err = parseWhitelist(&s, os.Args[2], false); err != nil {
			fmt.Println(err.Error())
			return
		}
	case "drop":
		if err = parseWhitelist(&s, os.Args[2], true); err != nil {
			fmt.Println(err.Error())
			return
		}
	default:
		log.SetOutput(ioutil.Discard)
		s.load()
		if c = client(path, s.Port, s.IsSecure(), false); c == nil {
			return
		}
		s, e := prettyjson.Marshal(c)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println(string(s))
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	var reloadCommands []string = []string{
		"genkey", "revoke",
		"whitelist", "drop",
	}
	if contains(os.Args[1], reloadCommands) && isRunning() {
		client("bwvreload", s.Port, s.IsSecure(), false)
	}
}

func parseWhitelist(s *server, w string, remove bool) error {
	s.load()
	var whitelist []string = strings.Split(w, ",")
	for _, addr := range whitelist {
		if net.ParseIP(os.Args[2]) == nil {
			ip, n, err := net.ParseCIDR(addr)
			if err != nil {
				return fmt.Errorf("Invalid IP or cidr range %s\n", addr)
			}
			if !n.IP.Equal(ip) {
				return fmt.Errorf("Cidr range %s is invalid, should be %s\n", addr, n)
			}
		}

		if remove {
			var newWhitelist []string = make([]string, 0)
			for _, netw := range s.Whitelist {
				if netw == addr {
					continue
				} else if containsIp(netw, addr) {
					return fmt.Errorf("Address %s is part of CIDR range %s which is not being removed", addr, netw)
				}
				newWhitelist = append(newWhitelist, netw)
			}
			s.Whitelist = newWhitelist
		} else {
			var exists bool = false
			for _, netw := range s.Whitelist {
				if addr == netw || containsIp(netw, addr) {
					exists = true
				}
			}
			if !exists {
				s.Whitelist = append(s.Whitelist, addr)
			}
		}
	}
	s.save()
	return nil
}

func isRunning() bool {
	var (
		status *dbus.UnitStatus
		err    error
	)
	status, err = unix.ServiceStatus(appName)
	return err == nil && status.SubState == "running"
}
