//go:build !windows
// +build !windows

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

package unix

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/notapipeline/bwv/pkg/bitw"

	// golangs openpgp is deprecated and frozen
	// as a result of this, we need a supported
	// fork so replacing with ProtonMails as this
	// is the most up to date.
	"github.com/ProtonMail/go-crypto/openpgp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Autoloader struct {
	bwv     *bitw.Bwv
	envPath string
}

// NewAutoloader creates a new autoloader object
//
// The autoloader pulls all values from the vault and iterates over them to
// discover ciphers marked for autoloading.
//
// As this function pulls all values from the vault and requires everything to
// be decrypted, it should only be called periodically as it is fairly resource
// intensive. Additionally it will load all attachments temporarily into memory
// during discovery, so it is not recommended to use this function on large
// vaults.
func NewAutoloader(bwv *bitw.Bwv) *Autoloader {
	var path string = filepath.Join(os.Getenv("HOME"), ".config", "bwv", "environment")

	if err := os.MkdirAll(path, 0700); err != nil {
		log.Fatalf("failed to create environment directory %q : error was %q", path, err)
	}

	return &Autoloader{
		bwv:     bwv,
		envPath: path,
	}
}

// Autoload scans the key vault and loads all keys containing a field "autoload"
// into the ssh-agent
//
// The autoload field can be set to "true" to load all attachments or a comma
// separated list of attachment names to load only those attachments.
//
// If the attachment is password protected, a custom field should be set on the
// cipher with the name of the attachment and the password as the value.
//
// If this field is not set, the function will instead look for a field named
// "password" and use that as the password for the attachment.
//
// If the attachment is an SSH key, it should contain `id_` to be recognised as
// such. Similarly, GPG keys can be loaded if the the filename ends with `.pgp`
func (a *Autoloader) AutoLoad(bwv *bitw.Bwv) error {
	var (
		ciphers []bitw.DecryptedCipher
		ok      bool
		errors  []error
	)

	if ciphers, ok = bwv.Get("*/*"); !ok {
		return fmt.Errorf("unable to load secrets from vault")
	}

	for _, c := range ciphers {
		var (
			autoload    string
			environment string
		)
		if autoload, ok = c.Fields["autoload"]; ok {
			e := a.addCipherKeys(autoload, &c)
			if len(e) > 0 {
				errors = append(errors, e...)
			}
		}

		if environment, ok = c.Fields["environment"]; ok {
			var environments []string = strings.Split(environment, ",")
			e := a.createEnvironmentFile(environments, &c)
			if e != nil {
				errors = append(errors, e)
			}
		}
	}

	if len(errors) > 0 {
		for _, err := range errors {
			log.Println(err)
		}
		return fmt.Errorf("failed to load all keys check logs for details")
	}
	return nil
}

// createEnvironmentFile creates an environment file for the given cipher
//
// Each cipher will be given its own environment file, named after the cipher
// created in the directory ~/.config/bwv/environment
//
// if the directory does not exists, it will be created with permissions 0700
// and the environment files created with permissions 0600.
func (a *Autoloader) createEnvironmentFile(environment []string, c *bitw.DecryptedCipher) (err error) {
	var (
		name      string
		envPrefix string
		file      *os.File
		envData   string
	)
	name = regexp.MustCompile(`[^a-zA-Z0-9 ]+`).ReplaceAllString(c.Name, "_")
	envPrefix = strings.ToUpper(name)

	name = filepath.Join(os.Getenv("HOME"), ".config", "bwv", "environment", name+".env")
	if _, err := os.Stat(name); err != nil {
		if file, err = os.Create(name); err != nil {
			return fmt.Errorf("cipher %q : failed to create environment file %q : error was %q", c.Name, name, err)
		}
		file.Close()

		// These files contain sensitive information, so we should set the
		// permissions to User read/write only - no group or other access.
		if err = os.Chmod(name, 0600); err != nil {
			return fmt.Errorf("cipher %q : failed to set permissions on thea environment file %q : error was %q", c.Name, name, err)
		}
	}

	// Open the file for writing but keep the permissions the same - user read/write, group/other none.
	if file, err = os.OpenFile(name, os.O_WRONLY, 0600); err != nil {
		return fmt.Errorf("cipher %q : failed to open environment file %q : error was %q", c.Name, name, err)
	}
	defer file.Close()

	for _, e := range environment {
		e = strings.TrimSpace(e)
		if v := c.Get(e); v != "" {
			envData += fmt.Sprintf("export %s_%s=%s\n", envPrefix, strings.ToUpper(e), v)
		} else if v, ok := c.Fields[e]; ok && v != "" {
			envData += fmt.Sprintf("export %s_%s=%s\n", envPrefix, strings.ToUpper(e), v)
		}
	}

	if _, err = file.WriteString(envData); err != nil {
		return fmt.Errorf("cipher %q : failed to write environment file %q : error was %q", c.Name, name, err)
	}
	return
}

// addCipherKeys adds the attachments from the given cipher to the agents
func (a *Autoloader) addCipherKeys(autoload string, c *bitw.DecryptedCipher) (errors []error) {
	var attachments map[string]string
	switch autoload {
	case "true":
		attachments = c.Attachments
	default:
		attachments = make(map[string]string)
		var names []string = strings.Split(autoload, ",")
		for _, name := range names {
			if _, ok := c.Attachments[name]; ok {
				attachments[name] = c.Attachments[name]
			}
		}
	}

	log.Printf("cipher %q : loading %d attachments", c.Name, len(attachments))
	for filename, attachment := range attachments {
		var (
			err      error
			b        []byte
			password string
			ok       bool
		)
		if b, err = base64.StdEncoding.DecodeString(attachment); err != nil {
			errors = append(errors, fmt.Errorf("cipher %q : failed to decode attachment %q : error was %q", c.Name, filename, err))
			continue
		}

		if password, ok = c.Fields[filename]; !ok {
			if password, ok = c.Fields["password"]; !ok {
				password = ""
			}
		}

		log.Printf("cipher %q : loading attachment %q", c.Name, filename)
		if strings.Contains(filename, "id_") && !strings.HasSuffix(filename, ".pub") {
			if err := a.addSSHKey(b, []byte(password), filename); err != nil {
				errors = append(errors, fmt.Errorf("failed to add key to ssh-agent: %w", err))
			}
		} else if strings.HasSuffix(strings.ToLower(filename), ".pgp") {
			if err := a.addPGPKey(b, []byte(password), filename); err != nil {
				errors = append(errors, fmt.Errorf("failed to add key to gpg-agent: %w", err))
			}
		}
	}
	return
}

// AddKey adds a key to the ssh-agent
func (a *Autoloader) addSSHKey(key, passphrase []byte, filename string) error {
	var (
		socket string
		conn   net.Conn
		err    error
		client agent.ExtendedAgent
		sshKey interface{}
	)

	if passphrase != nil {
		if sshKey, err = ssh.ParseRawPrivateKeyWithPassphrase(key, passphrase); err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	} else {
		if sshKey, err = ssh.ParseRawPrivateKey(key); err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	if socket = os.Getenv("SSH_AUTH_SOCK"); socket == "" {
		return fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	if conn, err = net.Dial("unix", socket); err != nil {
		return fmt.Errorf("failed to connect to ssh-agent: %w", err)
	}
	defer conn.Close()

	client = agent.NewClient(conn)
	if err := client.Add(agent.AddedKey{
		PrivateKey:       sshKey,
		Comment:          "bwv aded key" + filename,
		LifetimeSecs:     0,
		ConfirmBeforeUse: false,
	}); err != nil {
		return fmt.Errorf("failed to add key to ssh-agent: %w", err)
	}
	return nil
}

// getFingerprint returns the fingerprint of a given PGP key
//
// The fingerprint of the key is required to lookup the key in
// the gpg-agent in order to retrieve the keygrip(s).
func (a *Autoloader) getFingerprint(key []byte) (string, error) {
	var (
		els         openpgp.EntityList
		el          *openpgp.Entity
		err         error
		fingerprint string
	)

	if els, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(key)); err != nil {
		return "", fmt.Errorf("failed to read armored key ring: %w", err)
	}

	if len(els) != 1 {
		return "", fmt.Errorf("expected 1 key in armored key ring, got %d", len(els))
	}

	el = els[0]

	fingerprint = hex.EncodeToString(el.PrimaryKey.Fingerprint[:])
	return fingerprint, nil
}

// getKeygrips returns all keygrips for a given PGP key
//
// Each part in the key contains a keygrip which identifies the public key
// parameters expressed as a sha1 hash of length 20.
func (a *Autoloader) getKeygrips(fingerprint string) (kg []string, err error) {
	var (
		stdout  strings.Builder
		stderr  strings.Builder
		gpgCmd  *exec.Cmd
		gpgArgs []string = []string{
			"--with-keygrip", "--with-colons",
			"--list-secret-keys", fingerprint,
		}
	)

	gpgCmd = exec.Command("gpg", gpgArgs...)
	gpgCmd.Stdout = &stdout
	gpgCmd.Stderr = &stderr

	if err = gpgCmd.Run(); err != nil {
		printBuffers(&stdout, &stderr)
		err = fmt.Errorf("failed to get keygrip: %w", err)
		return
	}

	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "grp") {
			kg = append(kg, strings.Split(line, ":")[9])
		}
	}

	if len(kg) == 0 {
		err = fmt.Errorf("failed to get keygrip for key %q", fingerprint)
		return
	}

	return
}

// unlockKeys unlocks all keys with the given keygrip
//
// The keygrip is used to set the passphrase for the key using the command
// /usr/lib/gnupg2/gpg-preset-passphrase
//
// If this command fails, the key will still be loaded into the agent, but will
// require the user to enter the passphrase manually.
func unlockKeys(kg string, passphrase []byte) error {
	var (
		gpgCmd *exec.Cmd
		err    error
		stdout strings.Builder
		stderr strings.Builder
		reader bytes.Reader = *bytes.NewReader(passphrase)
	)

	gpgCmd = exec.Command("/usr/lib/gnupg2/gpg-preset-passphrase", "-c", kg)
	gpgCmd.Stdin = &reader
	gpgCmd.Stdout = &stdout
	gpgCmd.Stderr = &stderr

	if err = gpgCmd.Run(); err != nil {
		printBuffers(&stdout, &stderr)
		return fmt.Errorf("failed to set passphrase: %w", err)
	}

	return nil
}

// AddKey adds a key to the gpg-agent
//
// This is mainly a wrapper to the `gpg` command and will feed the key into
// stdin of the command. For the key passphrase to work, `gpg` must be configured
// to use the `loopback` pinentry mode.
func (a *Autoloader) addPGPKey(key, passphrase []byte, filename string) error {
	var (
		stdout  strings.Builder
		stderr  strings.Builder
		gpgCmd  *exec.Cmd
		reader  bytes.Reader = *bytes.NewReader(key)
		gpgArgs []string     = []string{
			"--batch", "--yes",
			"--pinentry-mode", "loopback",
		}
		err         error
		fingerprint string
		keygrips    []string
	)

	if fingerprint, err = a.getFingerprint(key); err != nil {
		return fmt.Errorf("failed to get fingerprint: %w", err)
	}

	if passphrase != nil {
		gpgArgs = append(gpgArgs, "--passphrase", string(passphrase))
	}
	gpgArgs = append(gpgArgs, "--import", "-")

	gpgCmd = exec.Command("gpg", gpgArgs...)

	gpgCmd.Stdin = &reader
	gpgCmd.Stdout = &stdout
	gpgCmd.Stderr = &stderr

	if err = gpgCmd.Run(); err != nil {
		printBuffers(&stdout, &stderr)
		return fmt.Errorf("failed to start gpg command: %w", err)
	}

	printBuffers(&stdout, &stderr)

	if keygrips, err = a.getKeygrips(fingerprint); err != nil {
		return fmt.Errorf("failed to get keygrip: %w", err)
	}

	for _, kg := range keygrips {
		if err = unlockKeys(kg, passphrase); err != nil {
			return fmt.Errorf("failed to unlock keys: %w", err)
		}
	}

	return nil
}

// printBuffers prints the contents of the stdout and stderr buffers
func printBuffers(stdout, stderr *strings.Builder) {
	for _, b := range strings.Split(stderr.String(), "\n") {
		if len(strings.TrimSpace(b)) > 0 {
			log.Println("stderr:", b)
		}
	}
	for _, b := range strings.Split(stdout.String(), "\n") {
		if len(strings.TrimSpace(b)) > 0 {
			log.Println("stdout:", b)
		}
	}
}
