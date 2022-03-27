A Cryptographic ABE Padlock
===========================

This is a simplification of the attribute-based-encryption padlock concept.
This implementation is just focusing on getting the language right first,
and using BLS Elliptic Curves, so that there are proper point hashes.

This means that we should be able to publicly encrypt to a set of attributes
without involving the CA.  The CA will only be needed to issue certificates.


A user makes a request to a CA, asking that it attest to some set of attributes.
The CA can refuse to sign it, or to add other attributes.

> I am a citizen of the US, and verified not a citizen of Saudi Arabia.  This is my email address, and I am an adult.

```json
[
	"citizenship:!SA",
	"citizenship:US",
	"email:rob.fielding@gmail.com",
	"age:adult"
]
```

> A different user.  Also verified to be not a citizen of China, and a dual citizen of Netherlands and Israel.  Also an adult with an email to be attested.

```json
[
	"citizenship:!CN",
	"citizenship:!SA",
	"citizenship:NL",
	"citizenship:IL",
	"email:bob@gmail.com",
	"age:adult"
]
```

When users submit their public, and non-sensitive certificate requests to a CA, they get back a secret certificate; that could well be inserted into a JWT token.
A JWT token would allow it to be used in an http header; provided that the number of facts is not very large.
The expiration date would not be cryptographically enforceable, but the tooling could refuse at a different level.

> The signer is public.  The facts are private, and should not be shared.  This json struct is a secret for the user. The facts are signed _individually_.

```json
{
  "signer": "EmtgKiWirc0BgesmSuFfaF+cvhxjb6jpCNQ0ouKZKGZDgCGgJtPvhwol1d0LHTbGEdi+BxKsa6aliyftVdJ3PLdeJEZWCJ2WrByytzym2CVNc21iR8ZE3pdCKHikkhQRC3FOU/MgSY2ShluKFyJ5y3fJAjwD3BKzupNP+rWpAZ7srM3ybnChUjgw1TK7p4HXGX7DkeUS7jseNJm11x88pKVx9ANBynH7Y4tF5iH9d9wbiWE3ZFsajPKHE17h9e4S",
  "facts": {
    "age:adult": "A35WCknGj0ld9O5NS1dn6BT43xcK0oI+zNOoJ6BXfw7lhMSM2wzJ3nH705NmOm05A5CcHNjH22/6pFLb5kXgWS220oKq3/uyS1GWEcylU610XnmIaMFFIvTo8OnLZuer",
    "citizenship:!SA": "DQ0IKUWtzorMcvn2UZUeQPrk+P/smw1flpYV+GOAc81qqOcBExzE9ht6MT6+vwBKCrWHbYsuwxnBWLX76wAwAHLHQ/QwOKo9CuC491iCukeDF64KLmtwobbBOENpkycc",
    "citizenship:US": "EiQhsVHvU18+IYUeUQb18ZxxQpzLNrYfLvqvfaQm3UZbzSB/Mi5EVBuj3ScsYFBZAw1MxLukZFai9Ak+pR/Shi1ZhZ5aCGjRQ6qJXKucroebimIdNV3YABmo3vB4vzRF",
    "email:rob.fielding@gmail.com": "D8Jja59zg7zgE27eMexHEnG5WhQVcXrFgxHoSc828/blmr+L0g1zSXmAbHKp32OIAiKTPZNEi+JSGVAQFPkdeiCMQ3dDRLDix9p+2XWRUu74QjGf81JqeiNwVAOqf6/N"
  }
}
```

It was created by the CA with:

```bash
# padlock command as run by the CA who has a request to make a user
# --priv is a secret for the private key.  it must have enough entropy to be secure (ie: 256-bits)
# --facts are the facts that are requested to be testified to
# The output is the secret cert.  Encoding this as a JWT makes sense. (TODO).
# That would mean that an expiration date should be requested.

padlock --priv farkfark --facts ./requests/alice.request.json > ./users/alice.cert.json
``` 

If Alice wants to make a padlock, it can be written to work for her signing domain, the public signer.
The padlock's creation need not involve the CA; and it can be created offline.

> Given a blueprint for a padlock, a padlock can be created.

```json
go run main.go --cert ./users/alice.cert.json --blueprint ./blueprints/isAdultCit.blueprint.json > ./padlocks/isAdultCit.padlock.json
```

Given a blueprint that has been compiled to a padlock, we can generate specific target keys (or random key material).  The blueprint is sensitive information,
and it should be destroyed after the padlock is created.

> We want to generate from a cert and a blueprint.  Use random keys that we can use our own certificate to unlock and extract them.
```json

{
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
					{"some": ["citizenship", "!SA"]},
					{"some": ["age", "adult"]}
				]
			}
		}
	}
}
```
