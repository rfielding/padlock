package main

import (
	"github.com/rfielding/padlock/abe"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	// Set up the CA
	priv := abe.Hs("farkfark")
	pub := abe.CA(priv)

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
						{"every": ["age", "adult"]}
					]
				}
			}
		}
	}`, pub, keyMap)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Blueprint: %s\n", e.Blueprint)

	// Create a certificate
	alice, err := abe.Issue(
		priv,
		[]string{
			"citizenship:!SA",
			"citizenship:US",
			"email:rob.fielding@gmail.com",
			"age:adult",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("certificate alice: %s\n", abe.AsJson(alice))

	// Attempt an unlock
	granted, err := e.Unlock(alice)
	if err != nil {
		panic(err)
	}
	for k, v := range granted {
		fmt.Printf("alice granted %s: %s\n", k, hex.EncodeToString(v))
		fmt.Printf("alice expected %s: %s\n", k, hex.EncodeToString(keyMap[k]))
	}
}
