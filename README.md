A Cryptographic ABE Padlock
===========================

This is a simplification of the attribute-based-encryption padlock concept.
This implementation is just focusing on getting the language right first,
and using BLS Elliptic Curves, so that there are proper point hashes.

This means that we should be able to publicly encrypt to a set of attributes
without involving the CA.  The CA will only be needed to issue certificates.

# Smoke Test

```bash
./cmd/padlock/testit.sh
```

# Facts

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

# Users

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

padlock \
  --priv farkfark \
	--facts ./requests/alice.request.json \
	> ./users/alice.cert.json
```

# Blueprints and Padlocks

If Alice wants to make a padlock, it can be written to work for her signing domain, the public signer.
The padlock's creation need not involve the CA; and it can be created offline.

> Given a blueprint for a padlock, a padlock can be created.

```bash
padlock \
  --cert ./users/alice.cert.json \
	--blueprint ./blueprints/isAdultCit.blueprint.json \
	> ./padlocks/isAdultCit.padlock.json
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

This padlock means:

- Rendering hint of a label like ADULT, with a black background, white foreground.
- A Read key can ben generated by meeting isAdultCit criteria.
- A Write key can be generated by meeting isAdultCit and having one of the emails.
- "some" means that first arg is fact name, and other args are required value (_or_ logic).
- "every" is much like some, except _every_ value is required (_and_ logic).

The _expr_ language supports:

- _and_, _or_ nested arbitrarily
- _requires_ is a reference to an existing case (no reference cycles allowed)
- _some_ for `["citizenship", "US", "IL"]` means fact `citizenship:US` or `citizenship:IL` is sufficient.
- _every_ for `["role", "admin", "user"]` means that `role:admin` and `role:user` are both required.
- By convention, negated facts are just going to use `!` in front of their values. They must be explicitly asserted to work.

When a user is applied to a padlock, keys are yielded.  
This is a form of public key secret derivation.
Instead of encrypting a file to a user, it can be encrypted to a padlock blueprint.
The facts in a user certificate determines if the correct keys are yielded.
This is the essence of `cpabe` (`ciphertext policy attribute based encryption`).

# Unlocks

```yaml
# alice private Certificate
{
  "signer": "EmtgKiWirc0BgesmSuFfaF+cvhxjb6jpCNQ0ouKZKGZDgCGgJtPvhwol1d0LHTbGEdi+BxKsa6aliyftVdJ3PLdeJEZWCJ2WrByytzym2CVNc21iR8ZE3pdCKHikkhQRC3FOU/MgSY2ShluKFyJ5y3fJAjwD3BKzupNP+rWpAZ7srM3ybnChUjgw1TK7p4HXGX7DkeUS7jseNJm11x88pKVx9ANBynH7Y4tF5iH9d9wbiWE3ZFsajPKHE17h9e4S",
  "facts": {
    "age:adult": "A35WCknGj0ld9O5NS1dn6BT43xcK0oI+zNOoJ6BXfw7lhMSM2wzJ3nH705NmOm05A5CcHNjH22/6pFLb5kXgWS220oKq3/uyS1GWEcylU610XnmIaMFFIvTo8OnLZuer",
    "citizenship:!SA": "DQ0IKUWtzorMcvn2UZUeQPrk+P/smw1flpYV+GOAc81qqOcBExzE9ht6MT6+vwBKCrWHbYsuwxnBWLX76wAwAHLHQ/QwOKo9CuC491iCukeDF64KLmtwobbBOENpkycc",
    "citizenship:US": "EiQhsVHvU18+IYUeUQb18ZxxQpzLNrYfLvqvfaQm3UZbzSB/Mi5EVBuj3ScsYFBZAw1MxLukZFai9Ak+pR/Shi1ZhZ5aCGjRQ6qJXKucroebimIdNV3YABmo3vB4vzRF",
    "email:rob.fielding@gmail.com": "D8Jja59zg7zgE27eMexHEnG5WhQVcXrFgxHoSc828/blmr+L0g1zSXmAbHKp32OIAiKTPZNEi+JSGVAQFPkdeiCMQ3dDRLDix9p+2XWRUu74QjGf81JqeiNwVAOqf6/N"
  }
}
# bob private Certificate
{
  "signer": "EmtgKiWirc0BgesmSuFfaF+cvhxjb6jpCNQ0ouKZKGZDgCGgJtPvhwol1d0LHTbGEdi+BxKsa6aliyftVdJ3PLdeJEZWCJ2WrByytzym2CVNc21iR8ZE3pdCKHikkhQRC3FOU/MgSY2ShluKFyJ5y3fJAjwD3BKzupNP+rWpAZ7srM3ybnChUjgw1TK7p4HXGX7DkeUS7jseNJm11x88pKVx9ANBynH7Y4tF5iH9d9wbiWE3ZFsajPKHE17h9e4S",
  "facts": {
    "age:adult": "A35WCknGj0ld9O5NS1dn6BT43xcK0oI+zNOoJ6BXfw7lhMSM2wzJ3nH705NmOm05A5CcHNjH22/6pFLb5kXgWS220oKq3/uyS1GWEcylU610XnmIaMFFIvTo8OnLZuer",
    "citizenship:!CN": "CfsjVKFLFkp6LMnSk5aAbMXEf1KxsG1YZAxz1WqN01yZ4wz35Kjo6wavOacPjgstESHGm7ja4usGNvRuXQ1+nUpeJGDJgEdBvTsVqZXXtGTIVoLGfw8PLmurQVlDgIzi",
    "citizenship:!SA": "DQ0IKUWtzorMcvn2UZUeQPrk+P/smw1flpYV+GOAc81qqOcBExzE9ht6MT6+vwBKCrWHbYsuwxnBWLX76wAwAHLHQ/QwOKo9CuC491iCukeDF64KLmtwobbBOENpkycc",
    "citizenship:IL": "EnUCmbWz6yj8E0UFy/PtgNHzoljTDyAwxbosWnWzYggyxj2aTZyANNdUWV/QXXspE+FwDsCi4KGNxSBw+nmLCKXX85thJHmWkB7bu1KTxZEAoTZQeE17aSdoq0kP/FiR",
    "citizenship:NL": "Fexi7QRRv32RNwGYhgaEXzfzz5F/jpOrqe0LfMpbk8jouIf4y6fxQ+d2SMdOKWX1DK3v/COK6oU8bwi9RPTrum08Y9GZDw78lWz3E7tg/ccyVBgpyXBBTJ1Bu92qfCDN",
    "email:bob@gmail.com": "Gb6k3VvMdcQg3jvijhPxMGw606VZbc2yraLVftjDaPAGUNBlEtLXf6nH814Uv0/HGY4xoB13l27pwKDPtAEWU3kJW0zYXqxflkQgzx9Mhh9FXc81nYMOgwU3Tvj8HqaQ"
  }
}
# alice Unlocks
{
  "Read": "m5qNBafsNTvahPnBuzF4wpneMAG16XBQjdyInEh/kso=",
  "Write": "PwCSenGTRe3UqDFlmdOzKIV5h1R/iIQwaGEWH/oJZH4="
}
# bob Unlocks
{
  "Read": "m5qNBafsNTvahPnBuzF4wpneMAG16XBQjdyInEh/kso="
}
```

Every user that has genuine signed facts for the same signer will generate the same keys during _unlock_.
The _unlock_ output can be used as key material for a decrypt key in the _Read_ case, and in the _Write_
case, it can be used to deterministically generate a signing key (TBD).  The point is to
be able to put on padlocks that can enforce _Read_ and _Write_ rules with _cpabe_.

```bash
./padlock \
  --cert ./users/alice.cert.json \
	--padlock ./padlocks/isAdultCit.padlock.json
```

In this case, a set of keys comes back by name.

# Mathematical Basis

A pairing function `e` ends up with the same value when the CA signing secret `s` and the file secret nonce `f` are swapped.
This is why it is possible to create a padlock without assistance from the CA, and to unlock without assistance from the CA;
such that the CA is only involved in attesting to facts about a user.

- A CA public key secretly signed with `s` paired with a sum of attributes signed with `f` can be used to make a padlock.
- A file public key secretly signed with `f` paired with a sum of attested attributes signed with `s`.

![pairing equation](https://render.githubusercontent.com/render/math?math=\color{gray}\hat%20e[s%20H1_0%2Bs%20H1_1%2B\cdots,f%20G2]=\hat%20e[f%20H1_0%2Bf%20H1_1%2B\cdots,s%20G2])

An Elliptic Curve pairing key is used to perform this task.
It is extremely important that:

- The curve has a proper point hash, so that values in the hash need not be secret.
- Given public hash values, the CA need not be involved in padlock creation.
- This is similar to Identity Based Encryption.  Exception IBE is one-attribute only.  IBE allows for encryption to be made to a chosen-text public key; such as an email address.  That way, encryption can be made to an email address, under the authority of a CA.  And the CA must issue the private key for that email address later.  This is the opposite of how public key crypto usually works, where there is no direct control over what the public key is, so that CAs need to explicitly sign public keys.  Because of this, we only need to trust that a CA won't issue a certificate with untruthful information in it.

> Warning! The use of this construction limits possibilities of collusion to individual files.  Two rogue users colluding such as an `age:adult` colluding with a non-adult from `citizen:US`.  There are claims made in some cpabe implementations that collusion is cryptographically impossible in all cases.  They use Lagrange Polynomial interpolation to mix attributes.  But in my implementations, the many ways I have tried, I have found subtle ways to collude on the same file (only) under the same CA.  This limits the disaster that could be caused by rogue users to individual files.  But it's TBD to figure out to limit collusion cryptographically in every case.  The implementation of the curve hides the raw values of the points, which makes the Lagrange Polynomial interpolation difficult to implement.
