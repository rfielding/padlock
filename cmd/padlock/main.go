package main

import (
	"github.com/rfielding/padlock/abe"
	//"github.com/cloudflare/circl/group"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ec "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"log"
	"sort"
)

func main() {
	// Set up the CA
	priv := abc.Hs("farkfark")
	pub := abc.CA(priv)

	// Plan the keys for the padlock
	W := sha256.Sum256([]byte("pencil"))
	R := sha256.Sum256([]byte("paper"))

	keyMap := map[string][]byte{"Write": W[:], "Read": R[:]}

	// Create the padlock
	e, err := abe.AsSpec(`{
		"label": "ADULT",
		"fg": "white",
		"bg": "black",
		"cases": {
			"isOwner": {
				"key": "Write",
				"expr": {
					"and": [
						{"requires": "isAdultCit"},
						{"some": ["email","rob.fielding@gmail.com","rrr00bb@yahoo.com"]}
					]
				}
			},
			"isAdultCit": {
				"key": "Read",
				"expr": {
					"and": [
						{"some": ["citizenship", "US", "NL"]},
						{"every": ["citizenship", "!SA"]},
						{"every": ["age", "adult", "driving"]}
					]
				}
			}
		}
	}`, pub, keyMap)
	if err != nil {
		panic(err)
	}

	fmt.Printf("eN: %s\n", abe.Blueprint)

	// Create a certificate
	alice, err := abe.Issue(
		priv,
		[]string{
			"citizenship:NL",
			"citizenship:!SA",
			"email:rob.fielding@gmail.com",
			"age:adult",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("alice: %s\n", abe.AsJson(alice))

	// Attempt an unlock
	granted, err := e.Unlock(alice)
	if err != nil {
		panic(err)
	}
	for k, v := range granted {
		fmt.Printf("granted %s: %s\n", k, hex.EncodeToString(v))
		fmt.Printf("expected %s: %s\n", k, hex.EncodeToString(keyMap[k]))
	}
}
