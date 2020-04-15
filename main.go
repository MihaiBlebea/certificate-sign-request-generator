package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
)

// Define arguments
var args = os.Args[1:]

func main() {
	name, err := getNameFromArgv()
	if err != nil {
		log.Fatal(err)
	}

	err = os.Mkdir(name, 0700)
	if err != nil {
		log.Fatal(err)
	}

	// Generate private key
	privateKey, err := generatePrivateKey(2048)
	if err != nil {
		log.Fatal(err)
	}

	encodedPrivateKey := encodePrivateKeyToPEM(privateKey)

	filePath := fmt.Sprintf("./%s/%s.key", name, name)
	err = writeKeyToFile(encodedPrivateKey, filePath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Key saved to: %s", filePath)

	// Generate certificate sign request
	subject := fmt.Sprintf("/CN=%s", name)
	csr, err := generateCertSignRequest(subject, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	filePath = fmt.Sprintf("./%s/%s.csr", name, name)
	err = writeKeyToFile(csr, filePath)
	if err != nil {
		log.Fatal(err)
	}

	// Generate yaml template
	base64EncodedCSR := encode64(csr)
	filePath = fmt.Sprintf("./%s/encoded-key.txt", name)
	err = writeKeyToFile([]byte(base64EncodedCSR), filePath)
	if err != nil {
		log.Fatal(err)
	}

	err = generateYamlCertificateSignRequest(name, base64EncodedCSR)
	if err != nil {
		log.Fatal(err)
	}
}

func getNameFromArgv() (string, error) {
	if len(args) < 1 {
		return "", errors.New("Name was not supplied. Please supply name as first argument")
	}
	return args[0], nil
}

func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func generateCertSignRequest(subject string, privateKey *rsa.PrivateKey) ([]byte, error) {
	subj := pkix.Name{
		CommonName: subject,
		// Country:            []string{"AU"},
		// Province:           []string{"Some-State"},
		// Locality:           []string{"MyCity"},
		// Organization:       []string{"Company Ltd"},
		// OrganizationalUnit: []string{"IT"}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csr := pem.EncodeToMemory(block)
	return csr, nil
}

func generateYamlCertificateSignRequest(name, encodedKey string) error {
	type Replace struct {
		Name    string
		Request string
	}

	yaml, err := template.ParseFiles("template.yaml")
	if err != nil {
		return err
	}

	filePath := fmt.Sprintf("./%s/%s-csr-definition.yaml", name, name)
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	err = yaml.Execute(f, Replace{name, encodedKey})
	if err != nil {
		return err
	}
	return nil
}
