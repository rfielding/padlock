#!/bin/bash

# Create Alice and Bob with the CA
go run main.go --priv farkfark --facts ./requests/bob.request.json > ./users/bob.cert.json
go run main.go --priv farkfark --facts ./requests/alice.request.json > ./users/alice.cert.json

# Alice creates a padlock (should be same result, as long as same signer
go run main.go --cert ./users/alice.cert.json --blueprint ./blueprints/isAdultCit.blueprint.json > ./padlocks/isAdultCit.padlock.json

echo alice private Certificate
cat ./users/alice.cert.json
echo bob private Certificate
cat ./users/bob.cert.json

echo alice Unlocks
go run main.go --cert ./users/alice.cert.json --padlock ./padlocks/isAdultCit.padlock.json
echo bob Unlocks
go run main.go --cert ./users/bob.cert.json --padlock ./padlocks/isAdultCit.padlock.json
