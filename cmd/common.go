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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "sigs.k8s.io/yaml"

	"github.com/hokaccha/go-prettyjson"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/notapipeline/bwv/pkg/bwv"
	"github.com/notapipeline/bwv/pkg/types"
)

// fatal is a wrapper around log.Fatalf that will print a stack trace if
// the debug flag is set
var fatal func(format string, v ...any) = func(format string, v ...any) {
	if clientCmd.Debug {
		debug.PrintStack()
	}
	log.Fatalf(format, v...)
}

// newBwvClient is indirected so tests can drive the commands without a server.
var newBwvClient = bwv.NewClient

// client returns a client for the bwv server described by the command flags.
//
// The retry budget is deliberately short: the shared transport retries for 15
// minutes, which suits the server's own calls to Bitwarden but leaves someone
// running `bwv secret/path` staring at a prompt when the daemon is down.
func client() (*bwv.Client, error) {
	return newBwvClient(bwv.Options{
		Server:     clientCmd.Server,
		Port:       clientCmd.Port,
		Token:      clientCmd.Token,
		SkipVerify: clientCmd.SkipVerify,
		Retry:      30 * time.Second,
	})
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
		t.AppendRow([]any{k, v})
	}
	t.Render()
	return nil
}

func toSecret(r map[string]any) error {
	var (
		name string
		ok   bool
		data = make(map[string][]byte)
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
		list []any
	)

	if list, ok = r.Message.([]any); ok {
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

	var structure any
	if err = json.Unmarshal(b, &structure); err != nil {
		return err
	}

	if b, err = prettyjson.Marshal(structure); err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
