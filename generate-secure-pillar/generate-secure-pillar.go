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
	"strings"
	"time"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/urfave/cli"
	yaml "gopkg.in/yaml.v2"
)

var githubToken string
var githubOrg string
var secretsFilePath string
var secretsString string
var outputFilePath string = os.Stdout.Name()
var pgpKeyName string
var secretName string
var publicKeyRing string
var secureKeyRing string
var encryptAll bool
var decryptAll bool
var debug bool
var recurseDir string
var randSrc = rand.NewSource(time.Now().UnixNano())

var usr, _ = user.Current()
var defaultPubRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
var defaultSecRing = filepath.Join(usr.HomeDir, ".gnupg/secring.gpg")

const defaultOrg = "Everbridge"
const defaultPillar = "atlas-salt-pillar"
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

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
			Name:        "pubring, pub",
			Value:       defaultPubRing,
			Usage:       "PGP public keyring",
			Destination: &publicKeyRing,
		},
		cli.StringFlag{
			Name:        "secring, sec",
			Value:       defaultSecRing,
			Usage:       "PGP private keyring",
			Destination: &secureKeyRing,
		},
		cli.StringFlag{
			Name:        "secure_name, n",
			Usage:       "secure variable name",
			Destination: &secretName,
		},
		// accepts STDIN as a source using the standard unix '-' command line syntax:
		// cat foo | ./generate-secure-pillar -f -
		cli.StringFlag{
			Name:        "secrets_file, f",
			Value:       os.Stdin.Name(),
			Usage:       "path to a file to be encrypted (a file name of '-' will read from STDIN)",
			Destination: &secretsFilePath,
		},
		cli.StringFlag{
			Name:        "output_file, o",
			Value:       os.Stdout.Name(),
			Usage:       "path to a file to be written (defaults to STDOUT)",
			Destination: &outputFilePath,
		},
		cli.StringFlag{
			Name:        "secret, s",
			Usage:       "secret string value to be encrypted",
			Destination: &secretsString,
		},
		cli.StringFlag{
			Name:        "pgp_key, k",
			Usage:       "PGP key name, email, or ID to use for encryption",
			Destination: &pgpKeyName,
		},
		cli.BoolFlag{
			Name:        "encrypt_all, a",
			Usage:       "encrypt all non-encrypted values in a file",
			Destination: &encryptAll,
		},
		cli.BoolFlag{
			Name:        "decrypt_all, d",
			Usage:       "decrypt all encrypted values in a file",
			Destination: &decryptAll,
		},
		cli.StringFlag{
			Name:        "recurse, r",
			Usage:       "recurse over all .sls files in the given path (implies --encrypt_all)",
			Destination: &recurseDir,
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "adds line number info to log output",
			Destination: &debug,
		},
	}

	// TODO: this unholy mess needs to be re-done
	app.Action = func(c *cli.Context) error {
		if debug {
			log.SetFlags(log.LstdFlags | log.Lshortfile)
		}

		if secretsFilePath == "-" {
			secretsFilePath = os.Stdin.Name()
		}
		secretsFilePath, _ = filepath.Abs(secretsFilePath)

		if decryptAll == true && secretsFilePath != os.Stdin.Name() {
			securePillar := readSlsFile(secretsFilePath)
			for k, v := range securePillar.Secure_Vars {
				if strings.Contains(v, pgpHeader) == true {
					fmt.Printf("%s: \"%s\"\n", k, decryptSecret(v))
				}
			}
		} else if recurseDir != "" {
			encryptAll = true
			info, err := os.Stat(recurseDir)
			if err != nil {
				log.Fatal(err)
			}
			if info.IsDir() {
				slsFiles := findSlsFiles(recurseDir)
				for _, file := range slsFiles {
					pillar := readSlsFile(file)
					if len(pillar.Secure_Vars) > 0 {
						writeSlsFile(file, fmt.Sprintf("%s.new", file))
					}
				}
			} else {
				log.Fatal(fmt.Sprintf("%s is not a directory", info.Name()))
			}

		} else {
			writeSlsFile(secretsFilePath, outputFilePath)
		}

		return nil
	}

	app.Run(os.Args)
}

func writeSlsFile(inFilePath string, outFilePath string) {
	inFilePath, _ = filepath.Abs(inFilePath)
	outFilePath, _ = filepath.Abs(outFilePath)
	sls := pillarBuffer(inFilePath)
	if sls.Len() == 0 {
		return
	}

	stdOut := false
	if outFilePath == os.Stdout.Name() {
		stdOut = true
	}

	err := ioutil.WriteFile(outFilePath, sls.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	if !stdOut {
		fmt.Printf("Wrote out to file: '%s'\n", outFilePath)
	}
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

	if slsPath != os.Stdin.Name() {
		filename, _ := filepath.Abs(slsPath)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			yamlData, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Fatal(err)
			}

			err = yaml.Unmarshal(yamlData, &securePillar)
			if err != nil {
				log.Print(fmt.Sprintf("Skipping %s: %s\n", filename, err))
				return securePillar
			}
		}
	} else {
		securePillar.Secure_Vars = make(map[string]string)
	}

	return securePillar
}

func encryptSecret(plainText string) (cipherText string) {
	pubringFile, err := os.Open(publicKeyRing)
	defer pubringFile.Close()
	if err != nil {
		log.Fatal(err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		log.Fatal("cannot read public keys: ", err)
	}
	publicKey := getKeyByID(pubring, pgpKeyName)

	var tmpfile bytes.Buffer
	if err != nil {
		log.Fatal(err)
	}

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&tmpfile)
	w, _ := armor.Encode(writer, "PGP MESSAGE", nil)
	plaintext, _ := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, nil, &hints, nil)
	fmt.Fprintf(plaintext, string(plainText))
	plaintext.Close()
	w.Close()
	writer.Flush()

	return tmpfile.String()
}

func decryptSecret(cipherText string) (plainText string) {
	privringFile, err := os.Open(secureKeyRing)
	defer privringFile.Close()
	if err != nil {
		log.Fatal(err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		log.Fatal("cannot read private keys: ", err)
	} else if privring == nil {
		log.Fatal(fmt.Sprintf("%s is empty!", secureKeyRing))
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if block.Type != "PGP MESSAGE" {
		log.Fatal(err)
	}

	md, err := openpgp.ReadMessage(block.Body, privring, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)

	return string(bytes)
}

func pillarBuffer(filePath string) (pillarData bytes.Buffer) {
	var buffer bytes.Buffer
	var cipherText string
	securePillar := readSlsFile(filePath)
	plainText := secretsString
	dataChanged := false

	if encryptAll == true && filePath != os.Stdin.Name() {
		for k, v := range securePillar.Secure_Vars {
			if strings.Contains(v, pgpHeader) == false {
				fmt.Printf("key[%s] value[%s]\n", k, v)
				cipherText = encryptSecret(v)
				securePillar.Secure_Vars[k] = cipherText
				dataChanged = true
			}
		}
	} else {
		cipherText = encryptSecret(plainText)
		securePillar.Secure_Vars[secretName] = cipherText
		dataChanged = true
	}

	if !dataChanged {
		return buffer
	}

	yamlBytes, err := yaml.Marshal(securePillar)
	if err != nil {
		log.Fatal(err)
	}
	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(yamlBytes))

	return buffer
}

func findSlsFiles(searchDir string) []string {
	fileList := []string{}
	filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() == false && strings.Contains(f.Name(), ".sls") {
			fileList = append(fileList, path)
		}
		return nil
	})

	return fileList
}
