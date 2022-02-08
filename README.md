A Cryptographic ABE Padlock
===========================

This is a simplification of the attribute-based-encryption padlock concept.
This implementation is just focusing on getting the language right first,
and using BLS Elliptic Curves, so that there are proper point hashes.

This means that we should be able to publicly encrypt to a set of attributes
without involving the CA.  The CA will only be needed to issue certificates.

The language is in JSON for defining the padlocks, like this:

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
						{"every": ["citizenship", "!SA"]},
						{"every": ["age", "adult", "driving"]}
					]
				}
			}
		}
	}
}
```

> Lablled with ADULT with black background and white font.  To calculate a Read key, you must be an adult citizen of the right countries, you must be a citizen of US or NL, and not a citizen of SA (to comply with some laws they have).  You must be of age adult and age driving.  The owner of this file can calculate a Write key as long as his email is rob.fielding@gmail.com or rrr00bb@yahoo.com

When creating the padlock, we must pass in the CA public key, and the target keys Read and Write that we wish to be able to generate.
The language is limited to Monotone expressions, where negated facts can be asserted explicitly.  When loaded, the `some` clause flattens out to `or` logic, and `every` flattens out to `and` logic.  In `some` and `every`, the first token is the field name.  This makes it compact to create padlocks with lots of complicated cases.  When flattened out into straight logic, the padlock looks like this:

```json
{
  "label": "ADULT",
  "fg": "white",
  "bg": "black",
  "unlocks": [
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:US",
        "email:rob.fielding@gmail.com"
      ],
      "k": "FDd6RtqWrj1uQ5RC9rws9RKc6N0lob47xOXHxZxcJqc=",
      "pubf": "Fi9R0lzDlKHGLL7qqkIStbZr69avMf/M4bcNZRggXJIppK1FAzfVsjxye7hgC4qrAQniQwTUDVBYRPIeBRNEvXTSZIy21sZlOqwKtmSlq/6nGR1DX/b1fDyG2S5WeXOh"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:US",
        "email:rrr00bb@yahoo.com"
      ],
      "k": "ACxkB5n179Wkk0xo9P16V9lVHx79jtcOnOpUj6VCx34=",
      "pubf": "DD69jjZfepc26Zj+9tJ/UhjGfZDWF8qnp/cHpQDH2vS8DFpwh+eAgkNoKcOtzYlzC1II2eg4KVJmZEXHnJ+fW/zXsiDHXxmCYGUAikw3KclgtzMLWIleJjBeHGigRxyr"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:NL",
        "email:rob.fielding@gmail.com"
      ],
      "k": "Nb1Chtp7GYRHNNV4oha1QIBshSKPBqhmwp7EmnGIoTI=",
      "pubf": "D9dWlTb77epFNjaGeInf9n6O0zjP+Tgf4NS0sOA2U0qNf3kMK0hVGUbShBTxq4cxCPt3NkuzuU+aUlj+9lL/N/+4yNduNaTviyvPU9RKnHmFUagZrE1+ENM4f99M4xNn"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:NL",
        "email:rrr00bb@yahoo.com"
      ],
      "k": "Kx+T5f8WF0GptbqODHgdHcQ90i123cV1o9hLIds8vSM=",
      "pubf": "EuxvLaE8N+qkxIKGxh8U1Exv4+mEVbe1lCnrg5gR1y+H25dTUncXczd1m0/VCOLSFdR4dCdmrwMrZNjghyFGqHwphxAgDkeuZHB4hrOc5/0eafo2+oDy7pS2578PROUw"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:US",
        "email:rob.fielding@gmail.com"
      ],
      "k": "QwURJRLGTYDMtSehwvjidEwhl9lEPd9/KfBgc6jmVlY=",
      "pubf": "CzvvVvAkFRV+jXkGesQzdYceC8gJgCJKwD1EUJncPJLV/wsVbq9Ai2KM9B6ByDaKEfd5dtMhwsxuW3j9Cj1pm2E8tsx+WNAHEQUGpokC7ZnHV5G0ZmJ40arnCesk1vDZ"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:US",
        "email:rrr00bb@yahoo.com"
      ],
      "k": "GICp46FXGWXZfyahM2G4dQbkdHrf+nRK2q9RejzMkW4=",
      "pubf": "CZ0NQS6zVzs/udCO1cpQZxGz51obQAjSdBOI54WOCc1xGQLiaMFVgjbt8XAia1K2GcQn+gekFgplNJw2N0cU2/Ye3lxsJUPyvQ1bJaPbENJJbe3ewFwcZ1VKwsoOJIMP"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:NL",
        "email:rob.fielding@gmail.com"
      ],
      "k": "N0sgh5M3CD1WRMGhKnjBhsf9u6ofP+xcWBdVi2Y1vKs=",
      "pubf": "B1hpsByfC7CCmOmpYynXFvn4FNE64T4c4DuHXgIqq2NgiR+Gomzn4Xx0WcKUx1vSAS3n590UwV3IpPuXgtMtAs/R2jSBd3ldp40Oe6rLnZ8zde2Jbn0RUNJvg39S35N6"
    },
    {
      "key": "Write",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:NL",
        "email:rrr00bb@yahoo.com"
      ],
      "k": "RjaPnSDqxsdwnat+2EmiQP698898t3oZllRw5ryio5I=",
      "pubf": "BAmT/Nns6zueHToAIqK/L2Pc6zDfC2Rcb0qf1Xu95VoFbUGP9RU7RDgf9g5OkYidArQ/xPV25uWM3KNxtf+yKtIH1zOKboHzD+InUaJgell1d6rgKYBplUjT5ivrWU8f"
    },
    {
      "key": "Read",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:US"
      ],
      "k": "CmPULUi1xf5KiUNlOBEooAE8M1jn0DjWLokibeI7wsk=",
      "pubf": "D+a4cP6fd7wzLogaxlhLqDlmDPjX3vYLO0FzT/iBiXqoa+gBUNgW0SNw12HTI5ZhElJ8yCsqNJ1hjVAceLY2wDhSxUKjthCdo5wtwAS66yvh9btsnaIAbrTB11mqa5gu"
    },
    {
      "key": "Read",
      "and": [
        "citizenship:!SA",
        "age:adult",
        "citizenship:NL"
      ],
      "k": "FZBf6cYmrB6zBKDvjHRMXUvChyokwgD8NQ0H8mEFUaw=",
      "pubf": "CNUtet/yxvAoVWoDCXPBm2CeM6rt2xE0FvJA0cY+V/nOGpp6LrZVdstHZhpLUCapFkUEXCRQCTxJYQ7vh2NBjcdjLqaG+iyrxvmWY3Bzoc6uzXUt1+o1MRMOHjDikmZn"
    },
    {
      "key": "Read",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:US"
      ],
      "k": "Kr3ExslfN2WyH+Rp43yTrrwOKlGbmFPGRUYij9evZ0U=",
      "pubf": "AKr0HcoXL4IbQR/s9ItlDmEdE/7M6hJxu9p4bftNmo2pFTsBt7Bxl/ulz/mFKoEfAGGRc8igMw01pbFbvHSIH0ewH/xvOfc/64BU7UzV2p4Qqdky3UJCvdt6hcQH2BJv"
    },
    {
      "key": "Read",
      "and": [
        "citizenship:!SA",
        "age:driving",
        "citizenship:NL"
      ],
      "k": "fNNZsX8XyTB2EC5CDTYK4vMjjTCys7dn5yWQqUGydsk=",
      "pubf": "F1+iyVRt2NuaCH+hJXVQKal5yopZJ4kj2/rko1zi7tsTLbHX6TtzuTbN4ofrPeheGfh1erAEVbexd3oz1uqdKRVKI5ekuH3cciRzPfn6mMtat/adr8QId/qzlBNg15eI"
    }
  ],
  "capub": "EmtgKiWirc0BgesmSuFfaF+cvhxjb6jpCNQ0ouKZKGZDgCGgJtPvhwol1d0LHTbGEdi+BxKsa6aliyftVdJ3PLdeJEZWCJ2WrByytzym2CVNc21iR8ZE3pdCKHikkhQRC3FOU/MgSY2ShluKFyJ5y3fJAjwD3BKzupNP+rWpAZ7srM3ybnChUjgw1TK7p4HXGX7DkeUS7jseNJm11x88pKVx9ANBynH7Y4tF5iH9d9wbiWE3ZFsajPKHE17h9e4S"
}
```

The various unlock cases require fields `and` together.  The value `k` is xored with a cryptographic operation on the `and` items, to produce the actual target key.  Each file has a public key `pubf` that allows padlocks to be created without any certificates, or targeting any particular user.

- When all items in `and` are passed through a function, the chosen `Key` is ultimately generated.  `Xor(k, Pair( sum_i[and_i], pubf)) == Read` is roughly how it's computed.
- This effectively gives us cryptographic enforcement of Read/Write privilege, for monotone (ie: `and` and `or` combinations with limited negation of individual facts) expressions.  This limitation exists because the witnesses are hashes of attributes signed with `capub` private key.


## TODO

The CA system still needs to be written, something I have done before in a different project `cpabe`.

- The certificate will be a curve that includes a bunch of points signed by the CA
- The owner of the certificate doesn't necessarily know all of the points in the certificate, as some may be derogatory
- A padlock can query the certificate for witnesses to values such as a witness of `citizen:NL`.

For example, encode each signed attribute into a polynomial.  Then use Lagrange polynomials to make the certificate into a (public!) curve.  But the points that created the curve can be obfuscated by recreating the curve with just enough points from `0,1,2,3,...` to recreate the curve.  This offers plausible deniability on derogatory attributes.  If the attributes are not publicly guessable, then they can actually be hidden from the user.

![lagrange polynomial](https://render.githubusercontent.com/render/math?math=\color{blue}L[x]=\sum_j%20Y_j[\prod_i^{i%20\ne%20j}\frac{x%20-%20X_j}{X_i%20-%20X_j}])

Replacing all `X_i` with `0,1,2,3,...` can hide the original points, while still pinning down the curve.  The curve ends up being a sort of MAC that we choose some points, and let others be arbitrary. It is a certificate as well.   
