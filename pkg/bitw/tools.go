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
package bitw

import (
	"context"
	"log"
	"os"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/peterh/liner"
)

func ReadPassword(prompt string) (string, error) {
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)
	defer line.Close()
	var (
		password string
		err      error
	)
	if password, err = line.PasswordPrompt(prompt); err != nil {
		if err == liner.ErrPromptAborted {
			line.Close()
			os.Exit(0)
		}
		return "", err
	}
	return password, nil
}

func ReadLine(prompt string) (string, error) {
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)
	defer line.Close()
	var (
		password string
		err      error
	)
	if password, err = line.Prompt(prompt); err != nil {
		if err == liner.ErrPromptAborted {
			line.Close()
			os.Exit(0)
		}
		return "", err
	}
	return password, nil
}

func syncStore(loginResponse *LoginResponse) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, transport.AuthToken{}, loginResponse.AccessToken)
	if err := Sync(ctx); err != nil {
		log.Fatal(err)
	}
	log.Println("Sync complete")
}
