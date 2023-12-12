//go:build !windows
// +build !windows

package unix

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/notapipeline/bwv/pkg/bitw"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Autoloader struct {
	bwv     *bitw.Bwv
	envPath string
}

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
			envData += fmt.Sprintf("%s_%s=%s\n", envPrefix, strings.ToUpper(e), v)
		} else if v, ok := c.Fields[e]; ok && v != "" {
			envData += fmt.Sprintf("%s_%s=%s\n", envPrefix, strings.ToUpper(e), v)
		}
	}

	if _, err = file.WriteString(envData); err != nil {
		return fmt.Errorf("cipher %q : failed to write environment file %q : error was %q", c.Name, name, err)
	}
	return
}

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
		err error
	)

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
	return nil
}

func printBuffers(stdout, stderr *strings.Builder) {
	for _, b := range strings.Split(stderr.String(), "\n") {
		log.Println("stderr:", b)
	}
	for _, b := range strings.Split(stdout.String(), "\n") {
		log.Println("stdout:", b)
	}
}
