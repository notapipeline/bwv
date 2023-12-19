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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "sigs.k8s.io/yaml"

	"github.com/hokaccha/go-prettyjson"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

// fatal is a wrapper around log.Fatalf that will print a stack trace if
// the debug flag is set
var fatal func(format string, v ...interface{}) = func(format string, v ...interface{}) {
	if clientCmd.Debug {
		debug.PrintStack()
	}
	log.Fatalf(format, v...)
}

// getSecretsFromUserEnvOrStore is a wrapper around tools.GetSecretsFromUserEnvOrStore
var getSecretsFromUserEnvOrStore func(v bool) map[string][]byte = tools.GetSecretsFromUserEnvOrStore

// getKdf reads kdf info from the local bwv server for encrypting data sent to
// the server
func getKdf() (kdf types.KDFInfo) {
	var ctx context.Context = context.Background()
	var localAddress string = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
	if err := transport.DefaultHttpClient.Get(ctx, localAddress+"/api/v1/kdf", &kdf); err != nil {
		fatal("unable to get kdf info: %q", err)
	}
	return
}

// getEncryptedToken encrypts the token using the password and email address
func getEncryptedToken() string {
	var (
		secrets map[string][]byte = getSecretsFromUserEnvOrStore(false)
		err     error
		token   string
		kdf     types.KDFInfo = getKdf()
	)

	if clientCmd.Token == "" {
		if t, ok := secrets["BW_CLIENTSECRET"]; ok {
			clientCmd.Token = string(t)
		} else {
			clientCmd.Token = string(secrets["BW_PASSWORD"])
		}
	}

	if clientCmd.Token == "" {
		if err = loadClientConfig(); err != nil {
			return ""
		}
	}

	token, err = crypto.Encrypt(secrets["BW_PASSWORD"], string(secrets["BW_EMAIL"]), clientCmd.Token, kdf)
	if err != nil {
		fatal("failed to encrypt token : %q", err)
	}

	return token
}

func printResponse(r types.SecretResponse) error {
	switch clientCmd.Output {
	case "yaml":
		return printYAML(r)
	case "secret":
		return printSecret(r)
	case "table":
		return printTable(r)
	case "json":
		fallthrough
	default:
		return printJSON(r)
	}
}

func printTable(r types.SecretResponse) error {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	var ok bool
	if _, ok = r.Message.(map[string]any); !ok {
		log.Println("Unable to print response as table")
		return printJSON(r)
	}

	t.AppendHeader(table.Row{"Key", "Value"})
	for k, v := range r.Message.(map[string]any) {
		t.AppendRow([]interface{}{k, v})
	}
	t.Render()
	return nil
}

func toSecret(r map[string]any) error {
	var (
		name string
		ok   bool
		data map[string][]byte = make(map[string][]byte)
		b    []byte
		err  error
	)

	if name, ok = r["name"].(string); !ok {
		name = "CHANGEME"
	}

	for k, v := range r {
		switch k {
		case "name", "revision_date",
			"folder_id", "id":
			continue
		}
		if v, ok := v.(string); ok {
			data[k] = []byte(v)
		}

		if v, ok := v.(map[string]any); ok {
			for kk, vv := range v {
				data[k+"."+kk] = []byte(vv.(string))
			}
		}
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Data: data,
		Type: "Opaque",
	}

	fmt.Println("---")
	if b, err = kyaml.Marshal(secret); err != nil {
		return err
	}

	fmt.Println(string(b))

	return nil
}

// printSecret prints the response from the server in a kubernetes secret format
func printSecret(r types.SecretResponse) error {
	var (
		ok   bool
		err  error
		list []interface{}
	)

	if list, ok = r.Message.([]interface{}); ok {
		for _, v := range list {
			if err = toSecret(v.(map[string]any)); err != nil {
				return err
			}
		}
		return nil
	}

	return toSecret(r.Message.(map[string]any))
}

func printYAML(r types.SecretResponse) error {
	var (
		b   []byte
		err error
	)
	if b, err = kyaml.Marshal(r.Message); err != nil {
		return err
	}

	fmt.Println(string(b))
	return nil
}

// printResponse prints the response from the server in a pretty format
func printJSON(r types.SecretResponse) error {
	var (
		b   []byte
		err error
	)
	if b, err = json.Marshal(r.Message); err != nil {
		return err
	}

	var structure interface{}
	if err = json.Unmarshal(b, &structure); err != nil {
		return err
	}

	if b, err = prettyjson.Marshal(structure); err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// loadClientConfig loads the client config from the config file
func loadClientConfig() (err error) {
	c := config.New()
	if err = c.Load(config.ConfigModeClient); err != nil {
		return err
	}

	if clientCmd.Token == "" {
		clientCmd.Token = c.Token
		if c.Token == "" {
			fatal("no token specified")
		}
	}

	if clientCmd.Server == "" {
		clientCmd.Server = c.Address
		if c.Address == "" {
			clientCmd.Server = "localhost"
		}
	}

	if clientCmd.Port == 0 {
		clientCmd.Port = c.Port
		if c.Port == 0 {
			clientCmd.Port = bitw.DefaultPort
		}
	}

	return
}
