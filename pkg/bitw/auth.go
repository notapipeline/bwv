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
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

type preLoginRequest struct {
	Email []byte `json:"email"`
}

// urlValues takes pairs of strings and returns a url.Values object
func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

// ApiLogin retrieves an API token from the Bitwarden API by sending the
// users client_id and client_secret.
func (b *Bwv) ApiLogin(s map[string][]byte) (*types.LoginResponse, error) {
	log.Println("executing api login")
	var (
		err   error
		lr    types.LoginResponse
		login url.Values = urlValues(
			"grant_type", "client_credentials",
			"scope", "api",
			"client_id", string(s["BW_CLIENTID"]),
			"client_secret", string(s["BW_CLIENTSECRET"]),
			"deviceType", "3",
			"deviceIdentifier", "aac2e34a-44db-42ab-a733-5322dd582c3d",
			"deviceName", "firefox",
		)
	)

	// URL values cannot be retried and on failure are likely to kill the process
	//
	// As in most instances a delayed retry will succeed, we can wrap this here
	// to try keep the process alive by adding a longer delay.
	for i := 0; i < 5; i++ {
		ctx := context.Background()
		err = transport.DefaultHttpClient.Post(ctx, b.Endpoint.IdtServer+"/connect/token", &lr, login)
		if err == nil {
			break
		}
		<-time.After(time.Duration(5) * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("Could not login: %w", err)
	}

	if b.Secrets, err = cache.Instance(s["BW_PASSWORD"], s["BW_EMAIL"], lr.KDFInfo); err != nil {
		return nil, fmt.Errorf("Could not create secret cache: %w", err)
	}

	return &lr, nil
}

// UserLogin retrieves an API token from the Bitwarden API by sending the
// users hashed password and email address along with the two-factor auth token
//
// # Users will be prompted to enter the 2FA token on the command line if required
//
// This method should not be used for background services - use ApiLogin instead
func (b *Bwv) UserLogin(hashedPassword, email string) (*types.LoginResponse, error) {
	log.Println("executing user login")
	login := urlValues(
		"grant_type", "password",
		"username", email,
		"password", hashedPassword,
		"scope", "api",
		"client_id", "browser",
		"deviceType", "3",
		"deviceIdentifier", "aac2e34a-44db-42ab-a733-5322dd582c3d",
		"deviceName", "firefox",
	)

	var lr types.LoginResponse
	ctx := context.Background()
	if err := transport.DefaultHttpClient.Post(ctx, b.Endpoint.IdtServer+"/connect/token", &lr, login); err != nil {
		var (
			tfa *transport.TwoFactorRequiredError
			ok  bool
		)
		log.Printf("error: %+v\n", err)
		if tfa, ok = err.(*transport.TwoFactorRequiredError); !ok {
			log.Println("two factor auth is mandatory but not enabled")
			return nil, err
		}

		for i := 0; i < 3; i++ {
			provider, token, err := twoFactorPrompt(tfa)
			if err != nil {
				return nil, fmt.Errorf("could not obtain two-factor auth token: %v", err)
			}
			login.Set("twoFactorProvider", strconv.Itoa(int(provider)))
			login.Set("twoFactorToken", token)
			login.Set("twoFactorRemember", "1")

			if err := transport.DefaultHttpClient.Post(ctx, b.Endpoint.IdtServer+"/connect/token", &lr, login); err != nil {
				var errsc *transport.TwoFactorRequiredError
				if errsc, ok = err.(*transport.TwoFactorRequiredError); ok && errsc.ErrorModel != nil {
					continue
				}
				return nil, fmt.Errorf("could not login via two-factor auth")
			}
			break
		}
	}

	return &lr, nil
}

// prelogin retrieves information about the users encryption such as the number
// of iterations to use for PBKDF2 and the memory and parallelism for Argon2.
//
// This information is public in that it can always be retrieved by POSTing the
// users email address to the prelogin endpoint however this is a heavily rate
// limited endpoint and is likely to be blocked if used too frequently.
func (b *Bwv) prelogin(password, email []byte) (hashed string, err error) {
	log.Println("executing pre-login stage")
	var preLogin types.KDFInfo

	// It is not recommended to add any retry against this endpoint
	// as it is heavily rate limited and will likely block the client
	// from starting if used too frequently. For this reason, this cannot
	// be wrapped in a retry function and will 400 Bad Request on failure.
	if err = transport.DefaultHttpClient.Post(context.Background(), b.Endpoint.ApiServer+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return "", fmt.Errorf("Could not retrieve pre-login data: %w", err)
	}

	if b.Secrets, err = cache.Instance(password, email, preLogin); err != nil {
		return "", fmt.Errorf("Could not create secret cache: %w", err)
	}
	b.Secrets.KDF = preLogin
	return b.Secrets.HashPassword(password), nil
}
