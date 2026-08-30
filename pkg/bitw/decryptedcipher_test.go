/*
 *   Copyright 2025 Martin Proffitt <mproffitt@choclab.net>
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
	"testing"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/types"
)

// newTestBwv returns a Bwv whose secret cache is unlocked with the same test
// vault key used by serve_test, so ciphers can be encrypted and decrypted for
// real rather than through a mock.
func newTestBwv(t *testing.T) *Bwv {
	t.Helper()
	cache.Reset()
	t.Cleanup(cache.Reset)

	const userKey = "2.i/7aEu9Pc3WI8hvaADB/Fg==|" +
		"gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/" +
		"19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|" +
		"uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4="

	secrets, err := cache.Instance([]byte("masterpw"), []byte("email@example.com"), types.KDFInfo{
		Type:        types.KDFTypePBKDF2,
		Iterations:  800000,
		Memory:      types.IntPtr(0),
		Parallelism: types.IntPtr(0),
	})
	if err != nil {
		t.Fatal(err)
	}

	var cs types.CipherString
	if err := cs.UnmarshalText([]byte(userKey)); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Unlock(cs); err != nil {
		t.Fatal(err)
	}

	b := NewBwv()
	b.Secrets = secrets
	return b
}

func encrypt(t *testing.T, b *Bwv, s string) types.CipherString {
	t.Helper()
	cs, err := b.Secrets.Encrypt([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestDecryptIdentity(t *testing.T) {
	b := newTestBwv(t)

	secret := types.Secret{
		Type: types.CipherIdentity,
		ID:   uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		Identity: &types.Identity{
			Title:          encrypt(t, b, "Mr"),
			FirstName:      encrypt(t, b, "Martin"),
			LastName:       encrypt(t, b, "Proffitt"),
			Username:       encrypt(t, b, "notapipeline"),
			Email:          encrypt(t, b, "me@example.com"),
			PostalCode:     encrypt(t, b, "39687"),
			Country:        encrypt(t, b, "Spain"),
			PassportNumber: encrypt(t, b, "123456789"),
		},
	}

	d := NewDecryptedCipher(b).Decrypt(secret, "Me")

	want := map[string]string{
		"title":          "Mr",
		"firstname":      "Martin",
		"lastname":       "Proffitt",
		"username":       "notapipeline",
		"email":          "me@example.com",
		"postalcode":     "39687",
		"country":        "Spain",
		"passportnumber": "123456789",
	}

	if len(d.Identity) != len(want) {
		t.Fatalf("got %d identity attributes %+v, want %d", len(d.Identity), d.Identity, len(want))
	}
	for k, v := range want {
		if d.Identity[k] != v {
			t.Errorf("identity[%q] = %q, want %q", k, d.Identity[k], v)
		}
	}

	// Identity attributes must be reachable as properties, case-insensitively,
	// and username must resolve to the identity when there is no login.
	for _, tc := range []struct{ property, want string }{
		{"firstname", "Martin"},
		{"FirstName", "Martin"},
		{"postalcode", "39687"},
		{"username", "notapipeline"},
		{"name", "Me"},
	} {
		if got := d.Get(tc.property); got != tc.want {
			t.Errorf("Get(%q) = %v, want %q", tc.property, got, tc.want)
		}
	}

	if got := d.Get("middlename"); got != nil {
		t.Errorf("Get(\"middlename\") = %v, want nil for an unset attribute", got)
	}
}

// A login's username must still win over the identity map, and a login cipher
// must not gain an identity block.
func TestDecryptLoginKeepsUsername(t *testing.T) {
	b := newTestBwv(t)

	secret := types.Secret{
		Type: types.CipherLogin,
		ID:   uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		Login: &types.Login{
			Username: encrypt(t, b, "loginuser"),
			Password: encrypt(t, b, "s3cret"),
		},
	}

	d := NewDecryptedCipher(b).Decrypt(secret, "test")
	if got := d.Get("username"); got != "loginuser" {
		t.Errorf("Get(\"username\") = %v, want %q", got, "loginuser")
	}
	if len(d.Identity) != 0 {
		t.Errorf("expected no identity attributes on a login cipher, got %+v", d.Identity)
	}
}
