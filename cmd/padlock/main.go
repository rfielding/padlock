package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rfielding/padlock/abe"
	"io/ioutil"
	"encoding/base64"
)

func unlockPadlock(certFile, padlockFile *string, key *string) {
	certBytes, err := ioutil.ReadFile(*certFile)
	if err != nil {
		panic(fmt.Sprintf("need a cert to know which public key to sign to: %v", err))
	}
	var cert abe.Certificate
	err = json.Unmarshal(certBytes, &cert)
	if err != nil {
		panic(fmt.Sprintf("Cannot unmarshal certificate: %v", err))
	}

	padlockBytes, err := ioutil.ReadFile(*padlockFile)
	if err != nil {
		panic(fmt.Sprintf("need a padlock to unlock: %v", err))
	}
	var e abe.Spec
	err = json.Unmarshal(padlockBytes, &e)
	if err != nil {
		panic(fmt.Sprintf("Error decoding spec: %v", err))
	}

	granted, err := e.Unlock(cert)
	if err != nil {
		panic(err)
	}

	if len(*key) > 0 {
		fmt.Printf("%s", base64.StdEncoding.EncodeToString(granted[*key]))
		return
	}
	fmt.Printf("%s\n", abe.AsJson(granted))
}

func issueCert(privStr, factsFile *string) {
	// Set up the CA
	priv := abe.Hs(*privStr)
	factsBytes, err := ioutil.ReadFile(*factsFile)
	if err != nil {
		panic(fmt.Sprintf("cannot open facts file %s: %v", *factsFile, err))
	}
	var facts []string
	err = json.Unmarshal(factsBytes, &facts)
	if err != nil {
		panic(fmt.Sprintf("cannot parse facts json: %v", err))
	}
	// Create a certificate
	alice, err := abe.Issue(
		priv,
		facts,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", abe.AsJson(alice))
}

func createPadlock(certFile, blueprintFile, readKeyStr, writeKeyStr *string) {
	blueprint, err := ioutil.ReadFile(*blueprintFile)
	if err != nil {
		panic(fmt.Sprintf("cannot open blueprints file %s: %v", *blueprintFile, err))
	}
	W, err := hex.DecodeString(*writeKeyStr)
	if err != nil {
		panic("cannot decode write key")
	}
	R, err := hex.DecodeString(*readKeyStr)
	if err != nil {
		panic("cannot decode read key")
	}
	certBytes, err := ioutil.ReadFile(*certFile)
	if err != nil {
		panic(fmt.Sprintf("need a cert to know which public key to sign to: %v", err))
	}
	var cert abe.Certificate
	err = json.Unmarshal(certBytes, &cert)
	if err != nil {
		panic(fmt.Sprintf("Cannot unmarshal certificate: %v", err))
	}

	pub, err := cert.Cert()
	if err != nil {
		panic(fmt.Sprintf("Cannot unmarshal certificate signer: %v", err))
	}
	keyMap := map[string][]byte{"Write": W[:], "Read": R[:]}
	e, err := abe.AsSpec(string(blueprint), pub, keyMap)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", abe.AsJson(e))
}

func main() {
	padlockFile := flag.String("padlock", "", "required to unlock: padlock file to unlock with cert")
	blueprintFile := flag.String("blueprint", "./blueprints/isAdultCit.padlock.json", "required to make padlock: blueprint file to generate a padlock")
	factsFile := flag.String("facts", "./requests/alice.request.json", "required to create cert: file with cert facts to be signed")
	certFile := flag.String("cert", "", "required to make a padlock, and unlock: cert file to make a padlock with a blueprint")
	privStr := flag.String("priv", "", "required to create cert: privateKeyPassword")
	rk := sha256.Sum256([]byte("Read"))
	wk := sha256.Sum256([]byte("Write"))
	readKeyStr := flag.String("readKey", hex.EncodeToString(rk[:]), "required to make a padlock: target read key for decrypt")
	writeKeyStr := flag.String("writeKey", hex.EncodeToString(wk[:]), "required to make a padlock: target write key for sign")
  key := flag.String("key", "", "pick a key to return when unlocking")
	flag.Parse()

	// Unlock a padlock
	if len(*padlockFile) > 0 {
		unlockPadlock(certFile, padlockFile, key)
		return
	}

	// We must be issuing a cert
	if len(*privStr) > 0 {
		issueCert(privStr, factsFile)
		return
	}

	// Create a padlock from a certificate and a blueprint
	if len(*certFile) > 0 {
		createPadlock(certFile, blueprintFile, readKeyStr, writeKeyStr)
		return
	}
}
