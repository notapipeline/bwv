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
