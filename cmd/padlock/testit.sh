#!/bin/bash

go run main.go --priv farkfark --facts ./requests/alice.request.json > ./users/alice.cert.json
go run main.go --cert ./users/alice.cert.json --blueprint ./blueprints/isAdultCit.blueprint.json > ./padlocks/isAdultCit.padlock.json
go run main.go --cert ./users/alice.cert.json --padlock ./padlocks/isAdultCit.padlock.json
