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
	"runtime/debug"

	"github.com/hokaccha/go-prettyjson"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

var fatal func(format string, v ...interface{}) = func(format string, v ...interface{}) {
	if clientCmd.Debug {
		debug.PrintStack()
	}
	log.Fatalf(format, v...)
}

var getSecretsFromUserEnvOrStore func(v bool) map[string][]byte = tools.GetSecretsFromUserEnvOrStore

func getKdf() (kdf types.KDFInfo) {
	var ctx context.Context = context.Background()
	var localAddress string = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
	if err := transport.DefaultHttpClient.Get(ctx, localAddress+"/api/v1/kdf", &kdf); err != nil {
		fatal("unable to get kdf info: %q", err)
	}
	return
}

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
