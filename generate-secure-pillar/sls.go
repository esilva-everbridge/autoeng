package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

func writeSlsFile(buffer bytes.Buffer, outFilePath string) {
	outFilePath, _ = filepath.Abs(outFilePath)

	stdOut := false
	if outFilePath == os.Stdout.Name() {
		stdOut = true
	}

	err := ioutil.WriteFile(outFilePath, buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	if !stdOut {
		fmt.Printf("Wrote out to file: '%s'\n", outFilePath)
	}
}

func readSlsFile(slsPath string) SecurePillar {
	var securePillar SecurePillar
	securePillar.Secure_Vars = make(map[string]string)

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

	return securePillar
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

func pillarBuffer(filePath string) bytes.Buffer {
	var buffer bytes.Buffer
	var cipherText string
	securePillar := readSlsFile(filePath)
	plainText := secretsString
	dataChanged := false

	if all == true && filePath != os.Stdin.Name() {
		for k, v := range securePillar.Secure_Vars {
			if strings.Contains(v, pgpHeader) == false {
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

	return formatBuffer(securePillar)
}

func plainTextPillarBuffer(inFile string) bytes.Buffer {
	securePillar := readSlsFile(inFile)
	for k, v := range securePillar.Secure_Vars {
		if strings.Contains(v, pgpHeader) == true {
			plainText := decryptSecret(v)
			securePillar.Secure_Vars[k] = plainText
		}
	}

	return formatBuffer(securePillar)
}

func formatBuffer(pillar SecurePillar) bytes.Buffer {
	var buffer bytes.Buffer

	yamlBytes, err := yaml.Marshal(pillar)
	if err != nil {
		log.Fatal(err)
	}

	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(yamlBytes))

	return buffer
}
