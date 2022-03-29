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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

const LOCALSERVER = "localhost.localdomain"

func client(path string, port int, secure, skip bool) interface{} {
	secrets := getSecretsFromEnvOrStore()
	token := secrets["BW_PASSWORD"]
	if secrets["BW_CLIENTSECRET"] != "" {
		token = secrets["BW_CLIENTSECRET"]
	}
	c := &http.Client{}
	var protocol string = "http"

	if secure {
		if skip {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
		protocol = "https"
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s://%s:%d/%s", protocol, LOCALSERVER, port, path), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if strings.Contains(netErr.Error(), "connection refused") {
				fmt.Println("Service not started or foreground server not active")
				fmt.Println("Please start the service with `bwv start` or run `bwv serve` to run in foreground")
				return nil
			}
		}
		if secure && !skip {
			log.Println("Retrying with insecure certificates")
			return client(path, port, secure, true)
		}
		return nil
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if resp.StatusCode == http.StatusBadRequest {
		if strings.Contains(string(body), "HTTP request to an HTTPS") {
			return client(path, port, true, false)
		}
	}

	var contents interface{}
	err = json.Unmarshal(body, &contents)
	if err != nil {
		fmt.Println(string(body))
		return nil
	}
	return contents
}
