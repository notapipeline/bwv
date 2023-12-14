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

package testdata

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

type TestData struct {
	AttachmentLookupResponse []byte
	LoginResponse            []byte
	SyncResponse             []byte
	Attachment               []byte
	AttachmentDecrypted      []byte
}

var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
)

func New() *TestData {
	var (
		t   *TestData = &TestData{}
		b   []byte
		err error
	)

	if b, err = os.ReadFile(basepath + "/login.json"); err != nil {
		log.Fatal(err)
	}
	t.LoginResponse = b

	if b, err = os.ReadFile(basepath + "/sync.json"); err != nil {
		log.Fatal(err)
	}
	t.SyncResponse = b

	if b, err = os.ReadFile(basepath + "/id_rsa.test.enc"); err != nil {
		log.Fatal(err)
	}
	t.Attachment = b

	if b, err = os.ReadFile(basepath + "/id_rsa.test"); err != nil {
		log.Fatal(err)
	}
	t.AttachmentDecrypted = b

	if b, err = os.ReadFile(basepath + "/attachmentlookup.json"); err != nil {
		log.Fatal(err)
	}
	t.AttachmentLookupResponse = b

	return t
}
