package main

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-github/github"
	"github.com/urfave/cli"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/oauth2"
)

var githubToken string
var githubOrg string
var githubRepo string
var pillarName string
var secretsFilePath string
var gpgKeyName string
var secretName string
var publicKeyRing string
var secureKeyRing string
var randSrc = rand.NewSource(time.Now().UnixNano())

var usr, _ = user.Current()
var defaultPubRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
var defaultSecRing = filepath.Join(usr.HomeDir, ".gnupg/secring.gpg")

const defaultOrg = "Everbridge"
const defaultPillar = "atlas-salt-pillar"

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Ed Silva",
			Email: "ed.silva@everbridge.com",
		},
	}
	app.Copyright = "(c) 2017 Everbridge, Inc."
	app.Usage = "add or update secure salt pillar content"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "token, t",
			Usage:       "github API token",
			Destination: &githubToken,
			EnvVar:      "GITHUB_TOKEN",
		},
		cli.StringFlag{
			Name:        "pubring, pub",
			Value:       defaultPubRing,
			Usage:       "GNUPG public keyring",
			Destination: &publicKeyRing,
		},
		cli.StringFlag{
			Name:        "secring, sec",
			Value:       defaultSecRing,
			Usage:       "GNUPG private keyring",
			Destination: &secureKeyRing,
		},
		cli.StringFlag{
			Name:        "github_org, o",
			Value:       defaultOrg,
			Usage:       "github organization",
			Destination: &githubOrg,
		},
		cli.StringFlag{
			Name:        "pillar_name, p",
			Value:       defaultPillar,
			Usage:       "secure pillar name",
			Destination: &pillarName,
		},
		cli.StringFlag{
			Name:        "secret_name, s",
			Usage:       "secret name",
			Destination: &secretName,
		},
		cli.StringFlag{
			Name:        "github_repo, r",
			Usage:       "github repo name",
			Destination: &githubRepo,
		},
		cli.StringFlag{
			Name:        "secrets_file, f",
			Usage:       "path to a yaml file to be encrypted",
			Destination: &secretsFilePath,
		},
		cli.StringFlag{
			Name:        "gpg_key, k",
			Usage:       "GPG key name to use for encryption",
			Destination: &gpgKeyName,
		},
	}

	app.Action = func(c *cli.Context) error {
		sls := parseTemplate()
		// fmt.Println(sls)

		// just write file with a matching name as the input with a .sls ext
		var extension = filepath.Ext(secretsFilePath)
		var name = secretsFilePath[0 : len(secretsFilePath)-len(extension)]
		var slsFile = fmt.Sprintf("%s.sls", name)
		err := ioutil.WriteFile(slsFile, []byte(sls), 0644)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Wrote out new file: '%s'\n", slsFile)

		// TODO: checkout pillar repo
		// checkoutPath, err := checkoutPillar("githubRepo")
		// if err != nil {
		//  log.Fatal(err)
		// }

		// // TODO: check for existing pillar file
		// exists := pillarFileExists(checkoutPath)

		// // TODO: check in or update new file
		// err = updatePillar("", exists)
		// if err != nil {
		//  fmt.Println("Unable to update pillar: ", err.Error())
		//  os.Exit(1)
		// }

		// defer os.Remove(checkoutPath)
		return nil
	}

	app.Run(os.Args)
}

func getKeyByID(keyring openpgp.EntityList, id string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.Name == id {
				return entity
			}
			if ident.UserId.Email == id {
				return entity
			}
			if ident.UserId.Name == id {
				return entity
			}
		}
	}

	return nil
}

func signSecret() (signedText []byte) {
	content, err := ioutil.ReadFile(secretsFilePath)
	if err != nil {
		log.Fatal(err)
	}
	pubringFile, err := os.Open(publicKeyRing)
	if err != nil {
		log.Fatal(err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		log.Fatal("cannot read public keys: ", err)
	}
	privringFile, err := os.Open(secureKeyRing)
	if err != nil {
		log.Fatal(err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		log.Fatal("cannot read private keys: ", err)
	}

	privateKey := getKeyByID(privring, gpgKeyName)
	publicKey := getKeyByID(pubring, gpgKeyName)

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	hints := openpgp.FileHints{IsBinary: false, FileName: tmpfile.Name(), ModTime: time.Time{}}
	w, _ := armor.Encode(tmpfile, "PGP MESSAGE", nil)
	plaintext, _ := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, privateKey, &hints, nil)
	fmt.Fprintf(plaintext, string(content))
	plaintext.Close()
	w.Close()

	content, err = ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		log.Fatal(err)
	}

	return content
}

func updatePillar(filePath string, exists bool) (err error) {
	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	// TODO: stuff goes here
	// if _, err := tmpfile.Write(content); err != nil {
	//  log.Fatal(err)
	// }
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	return nil
}

func pillarFileExists(checkoutPath string) (exists bool) {
	// TODO: fix me
	return false
}

func parseTemplate() (pillarData string) {
	var formatted string
	var content []byte
	signedText := signSecret()

	const pillarTemplate = `#!yaml|gpg

{{.SecretName}}: |
{{.SecureText}}
`

	scanner := bufio.NewScanner(strings.NewReader(string(signedText)))
	for scanner.Scan() {
		formatted = fmt.Sprintf("%s    %s\n", formatted, scanner.Text())
	}

	type Pillar struct {
		SecretName, SecureText string
	}
	pillar := Pillar{secretName, formatted}

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	t := template.Must(template.New("pillar").Parse(pillarTemplate))
	err = t.Execute(tmpfile, pillar)
	if err != nil {
		log.Fatal(err)
	}

	content, err = ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		log.Fatal(err)
	}

	return string(content)
}

func checkoutPillar() (path string, err error) {
	ctx := context.Background()

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	repo, resp, err := client.Repositories.Get(ctx, githubOrg, githubRepo)
	fmt.Println("resp: ", resp)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to get repo: %s", err.Error()))
		return "", err
	}

	// XXX - caller needs to clean up this dir
	tmpDir, _ := ioutil.TempDir("", "")

	cmd := exec.Command("git", "clone", repo.GetSSHURL(), fmt.Sprintf("%s/%s", tmpDir, githubRepo))
	err = cmd.Run()
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to clone pillar: %s", err.Error()))
		defer os.Remove(tmpDir)
		return "", err
	}

	return fmt.Sprintf("%s/%s", tmpDir, githubRepo), err
}
