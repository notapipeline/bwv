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
package tools

import (
	"encoding/binary"
	"log"
	"net"
)

func IsMachineNetwork(addr string) bool {

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, a := range addrs {
		log.Println(a, addr)
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(net.ParseIP(addr)) {
			return true
		}
	}
	return false
}

func IsExternalInterface(iface string) bool {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == iface {
			return i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0
		}
	}
	return false
}

// IsLocal returns true if the given address is a local address

// ContainsIp returns true if the given IP is in the given network
func ContainsIp(netw string, ip string) bool {
	if hosts := CidrHosts(netw); hosts != nil {
		for _, host := range hosts {
			if ip == host {
				return true
			}
		}
	}
	return false
}

// CidrHosts returns a slice of all the IPs in the given network
func CidrHosts(netw string) []string {
	var hosts []string

	_, ipv4Net, err := net.ParseCIDR(netw)
	if err != nil {
		return hosts
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)
	for i := start + 1; i <= finish-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	return hosts
}
