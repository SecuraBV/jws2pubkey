Tool to compute an RSA public key from two signed JWTs
======================================================

For a pentester assessing JWT security, it is possible that you encounter an application that produces RSA-signed 
tokens but does not reveal which public key was used to sign them. Determining this public key can however be useful
in some cases, such as:

- To perform an [HMAC/RSA algorithm confusion attack](https://portswigger.net/web-security/jwt/algorithm-confusion).
- To perform a [sign/encrypt confusion attack](https://github.com/latchset/jwcrypto/releases/tag/v1.4.0).
- To verify whether a key is reused in different contexts.
- To determine RSA key size.

The `RS256`, `RS384` and `RS512` algorithms use RSA with PKCS#1 v1.5 padding as their signature scheme. This has the 
property that you can compute the public key given two different messages and accompanying signatures. While this is 
not considered to be a vulnerability in the signature scheme (it's named a _public_ key after all), this property is
quite useful for the aforementioned use cases.

Given two distinct JWS's signed with the same key using one of the `RS*` algorithms, this tool will compute the public 
key and output it in JWK format.

Installation
------------

The script was succesfully tested with Python 3.10 and has a single dependency on GMP which can be downloaded as 
follows (create a virtualenv if needed):

```
pip install -r requirements.txt
```

If you prefer to run the tool from a Docker container, you can simply build it as follows:

```
docker build -t jws_get_rsa_pubkey .
```

Usage
-----

```
$ ./jws_get_rsa_pubkey.py -h
usage: jws_get_rsa_pubkey.py [-h] [-e E] [-f] jws1 jws2

This script attempts to find out the RSA public key used to sign two different
JWS's.works for the RS256, RS384 and RS512 algorithms. May take around a
minute to compute.

positional arguments:
  jws1        First JWS object.
  jws2        Second JWS object, signed by the same key but with a different
              payload.

options:
  -h, --help  show this help message and exit
  -e E        RSA public key exponent. If omitted, the most common values 
              will be tried.
  -f          Treat jws1 and jws2 as file names instead of JWS strings
              directly passed as arguments.
```

Example:

```
$ ./jws_get_rsa_pubkey.py -f sample-jws/sample{1,2}.txt | tee pubkey.jwk
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```

Docker example:

```
$ sudo docker run -it jws_get_rsa_pubkey $(cat sample-jws/sample1.txt) $(cat sample-jws/sample2.txt)
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```
