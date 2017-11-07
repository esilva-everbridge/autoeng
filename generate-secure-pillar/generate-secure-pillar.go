package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/urfave/cli"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	yaml "gopkg.in/yaml.v2"
)

var githubToken string
var githubOrg string
var update bool
var secretsFilePath string
var secretsString string
var outputFilePath string
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

// SecurePillar secure pillar vars
type SecurePillar struct {
	Secure_Vars map[string]string
}

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
			Name:        "secret_name, s",
			Usage:       "secret name",
			Destination: &secretName,
		},
		// accepts STDIN as a source using the standard unix '-' command line syntax:
		// cat foo | ./generate-secure-pillar -f -
		cli.StringFlag{
			Name:        "secrets_file, f",
			Usage:       "path to a file to be encrypted (a file name of '-' will read from STDIN)",
			Destination: &secretsFilePath,
		},
		cli.StringFlag{
			Name:        "output_file",
			Usage:       "path to a file to be written (defaults to STDOUT)",
			Destination: &outputFilePath,
		},
		cli.BoolFlag{
			Name:        "update, u",
			Usage:       "update the output file only (can't be stdout, will not overwrite existing files)",
			Destination: &update,
		},
		cli.StringFlag{
			Name:        "secret",
			Usage:       "secret string to be encrypted",
			Destination: &secretsString,
		},
		cli.StringFlag{
			Name:        "gpg_key, k",
			Usage:       "GPG key name to use for encryption",
			Destination: &gpgKeyName,
		},
	}

	app.Action = func(c *cli.Context) error {
		outfile := secretsFilePath
		stdOut := false

		if secretsFilePath == "-" {
			secretsFilePath = os.Stdin.Name()
			stdOut = true
			outfile = os.Stdout.Name()
		}
		secretsFilePath, _ := filepath.Abs(secretsFilePath)

		sls := pillarBuffer()

		err := ioutil.WriteFile(outfile, sls.Bytes(), 0644)
		if err != nil {
			log.Fatal(err)
		}
		if !stdOut {
			fmt.Printf("Wrote out to file: '%s'\n", secretsFilePath)
		}

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

func readSlsFile(slsPath string) SecurePillar {
	var securePillar SecurePillar

	if secretsFilePath != os.Stdin.Name() {
		filename, _ := filepath.Abs(slsPath)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			yamlData, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Fatal(err)
			}

			err = yaml.Unmarshal(yamlData, &securePillar)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else {
		securePillar.Secure_Vars = make(map[string]string)
	}

	return securePillar
}

func signSecret() (signedText string) {
	pubringFile, err := os.Open(publicKeyRing)
	if err != nil {
		log.Fatal(err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		log.Fatal("cannot read public keys: ", err)
	}
	publicKey := getKeyByID(pubring, gpgKeyName)

	var tmpfile bytes.Buffer
	if err != nil {
		log.Fatal(err)
	}

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&tmpfile)
	w, _ := armor.Encode(writer, "PGP MESSAGE", nil)
	plaintext, _ := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, nil, &hints, nil)
	fmt.Fprintf(plaintext, string(secretsString))
	plaintext.Close()
	w.Close()
	writer.Flush()

	return tmpfile.String()
}

func pillarBuffer() (pillarData bytes.Buffer) {
	signedText := signSecret()

	securePillar := readSlsFile(secretsFilePath)
	securePillar.Secure_Vars[secretName] = signedText

	yamlBytes, err := yaml.Marshal(securePillar)
	if err != nil {
		log.Fatal(err)
	}
	var buffer bytes.Buffer
	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(yamlBytes))
	// buffer.WriteTo(os.Stdout)

	return buffer
}

// func checkoutPillar() (path string, err error) {
// 	ctx := context.Background()

// 	ts := oauth2.StaticTokenSource(
// 		&oauth2.Token{AccessToken: githubToken},
// 	)
// 	tc := oauth2.NewClient(ctx, ts)

// 	client := github.NewClient(tc)

// 	repo, resp, err := client.Repositories.Get(ctx, githubOrg, githubRepo)
// 	fmt.Println("resp: ", resp)
// 	if err != nil {
// 		log.Fatal(fmt.Sprintf("Unable to get repo: %s", err.Error()))
// 		return "", err
// 	}

// 	// XXX - caller needs to clean up this dir
// 	tmpDir, _ := ioutil.TempDir("", "")

// 	cmd := exec.Command("git", "clone", repo.GetSSHURL(), fmt.Sprintf("%s/%s", tmpDir, githubRepo))
// 	err = cmd.Run()
// 	if err != nil {
// 		log.Fatal(fmt.Sprintf("Unable to clone pillar: %s", err.Error()))
// 		defer os.Remove(tmpDir)
// 		return "", err
// 	}

// 	return fmt.Sprintf("%s/%s", tmpDir, githubRepo), err
// }
