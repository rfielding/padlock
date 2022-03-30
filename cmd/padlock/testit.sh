#!/bin/bash

(
cd `dirname $0`
#go mod vendor
#go mod tidy
rm ./padlock
go build

# Create Alice and Bob with the CA
./padlock --priv farkfark --facts ./requests/bob.request.json > ./users/bob.cert.json
./padlock --priv farkfark --facts ./requests/alice.request.json > ./users/alice.cert.json

# Alice creates a padlock (should be same result, as long as same signer
./padlock --cert ./users/alice.cert.json --blueprint ./blueprints/isAdultCit.blueprint.json > ./padlocks/isAdultCit.padlock.json

echo alice private Certificate
cat ./users/alice.cert.json
echo bob private Certificate
cat ./users/bob.cert.json

echo alice Unlocks
./padlock --cert ./users/alice.cert.json --padlock ./padlocks/isAdultCit.padlock.json
echo bob Unlocks
./padlock --cert ./users/bob.cert.json --padlock ./padlocks/isAdultCit.padlock.json
echo pick a Read key from alice
./padlock --cert ./users/alice.cert.json --padlock ./padlocks/isAdultCit.padlock.json --key Read
echo
)
