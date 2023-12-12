package testdata

import (
	"fmt"
	"os"

	cache "github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/types"
)

var kdf = types.KDFInfo{
	Type:        types.KDFTypePBKDF2,
	Iterations:  800000,
	Memory:      types.IntPtr(0),
	Parallelism: types.IntPtr(0),
}

/*var data []string = []string{
	"filename.unc",
	"key that gets reencrypted",
	"username",
	"testuser",
	"password",
	"some-random-super-strong-password",
}*/

var data []string = []string{
	"some-cipher-with-attachment",
	"mocktoken",
	"mockfolder",
	"filename.unc",
}

func main() {
	var (
		err      error
		c        *cache.SecretCache
		secret   types.CipherString
		key, mac []byte
	)

	if c, err = cache.Instance("masterpw", "email@example.com", kdf); err != nil {
		fmt.Println(err)
		return
	}

	cs := types.CipherString{}
	if err = cs.UnmarshalText([]byte("2.i/7aEu9Pc3WI8hvaADB/Fg==|gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4=")); err != nil {
		fmt.Println(err)
		return
	}

	if err = c.Unlock(cs); err != nil {
		fmt.Println(err)
		return
	}

	var attachmentKey []byte = []byte("key that gets reencrypted")
	{
		key, mac, _ = crypto.DeriveStretchedMasterKey(attachmentKey, "email@example.com", kdf)
		var enc []byte = make([]byte, 0)
		enc = append(enc, key...)
		enc = append(enc, mac...)
		if secret, err = c.Encrypt(enc); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("attachment key:", secret.String())
	}

	// Encrypt the test key
	{
		var (
			b  []byte
			eb []byte
		)
		if b, err = os.ReadFile("testdata/id_rsa.test"); err != nil {
			fmt.Println(err)
			return
		}

		if eb, err = crypto.EncryptAes(b, types.AesCbc256_HmacSha256_B64, key, mac); err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("encrypted test key:", len(eb))
		if err = os.WriteFile("testdata/id_rsa.test.enc", eb, 0644); err != nil {
			fmt.Println(err)
			return
		}
	}

	for _, d := range data {
		var enc []byte = []byte(d)
		if secret, err = c.Encrypt(enc); err != nil {
			fmt.Println(err)
			return
		} else {
			fmt.Println(d+":", secret.String())
		}
	}
}
