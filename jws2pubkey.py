#!/usr/bin/env python3

"""This script attempts to find out the RSA public key used to sign two different JWS's. 
Works for the RS256, RS384 and RS512 algorithms."""

from gmpy2 import gcd, mpz

from base64 import urlsafe_b64encode, urlsafe_b64decode
from argparse import ArgumentParser, FileType
from math import log2, ceil
from threading import Thread, Event
import hashlib, json, re, sys, time

COMMON_EXPONENTS = [65537, 3, 5, 17, 257]

PKCS_HASH_IDS = {
    'sha256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'sha384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'sha512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

def numeric_find_n(m1, s1, m2, s2, e):
  # Computes n such that m1 == s1**e % n and m2 == s2**e % n, given that an n exists which is a product of two big primes.
  # Returns None on failure, meaning the e value is most likely incorrect.
  # Uses GMP for bigint operations, since it's a lot faster than built-in Python bigints.
  
  # Find upper and lower bounds for n, assuming the key's bit length is a power of two.
  s1 = mpz(s1)
  s2 = mpz(s2)
  lower_bound = mpz(max(m1, s1, m2, s2))
  upper_bound = mpz(2) ** ((lower_bound.bit_length() + 7) // 8 * 8)

  # s**e - m is a multiple of n; compute gcd of two of them to get a multiple that's probably quite small.
  xN = gcd(s1**e - m1, s2**e - m2)

  # Keep pulling out small prime factors until n is found.
  while xN % 2 == 0:
    xN //= 2
  prevfactors = [mpz(2)]
  factor = mpz(3)
  while xN > upper_bound or (m1 != pow(s1, e, xN) and xN > lower_bound):
    while xN % factor == 0:
      xN //= factor
    
    # Use sieve of Eratosthenes to find the next factor.
    prevfactors += [factor]
    factor += 2
    while any(factor % d == 0 for d in prevfactors):
      factor += 2
    
    

  return int(xN) if xN > lower_bound and m2 == pow(s2, e, xN) else None

def be_encode(intval):
  # Unsigned big-endian encoding of an integer, with no trailing zeros.
  if intval == 0:
    return b'\x00'
  else:
    le_result = []
    while intval > 0:
      le_result += [intval % 256]
      intval //= 256
    return bytes(reversed(le_result))

def be_decode(bs):
  # Big-endian decoding of a byte string to an integer.
  result = 0
  for octet in bs:
    result *= 256
    result += octet
  return result

def pkcs1v15_encode(hasher, msg, outlen):
  # RFC 3447 signature encoding.
  mhash = hashlib.new(hasher, msg).digest()
  suffix = PKCS_HASH_IDS[hasher] + mhash
  padding = b'\xff' * (outlen - len(suffix) - 3)
  return be_decode(b'\x00\x01' + padding + b'\x00' + suffix)

def find_pkcs1v15_pubkey(msg1, sig1, msg2, sig2, hasher, exponent=None):
  # Computes RSA public key given two messages and their PKCS1v1.5 signatures. 
  # Should be fast and succeed in the majority of cases.
  # Tries a few common e values if None is set.
  # Returns integers (n, e) on success. Returns None on failure.
  
  # Convert/hash bytes to bigints.
  m1 = pkcs1v15_encode(hasher, msg1, len(sig1))
  m2 = pkcs1v15_encode(hasher, msg2, len(sig2))
  s1 = be_decode(sig1)
  s2 = be_decode(sig2)

  # Try for each exponent.
  exponents = [exponent] if exponent else COMMON_EXPONENTS
  for e in exponents:
    n = numeric_find_n(m1, s1, m2, s2, e)
    if n:
      return n, e

  return None

def jwk_encode_rsakey(n, e):
  return json.dumps({
    'kty': 'RSA',
    'n': urlsafe_b64encode(be_encode(n)).decode().rstrip('='),
    'e': urlsafe_b64encode(be_encode(e)).decode().rstrip('='),
  })

def urlbase64_decode(s):
  # Python complains if there's too little padding, but not when there's too much.
  return urlsafe_b64decode(s + '==')

def find_jws_pubkey(jws1, jws2, exponent=None):
  # Find the public key two JWS objects are signed with, given that they use an RS* algorithm.
  # Returns an RSA key in JWK format on success, or None on failure.
  
  [h1, p1, s1] = jws1.split('.')
  [h2, p2, s2] = jws2.split('.')
  h1j = json.loads(urlbase64_decode(h1))
  h2j = json.loads(urlbase64_decode(h2))

  # JWS's must be distinct but use the same algorithm and key ID, if any.
  if s1 == s2:
    raise Exception('JWS\'s must be different.')
  if h1j['alg'] != h2j['alg']:
    raise Exception('JWS\'s do not use the same algorithm.')
  if h1j.get('kid') != h2j.get('kid'):
    raise Exception('JWS\'s have different Key IDs.')

  # This only works for RS* algorithms.
  algmatch = re.match(r'RS(?P<shabits>256|384|512)', h1j['alg'])
  if not algmatch:
    raise Exception('JWS\'s do not use RS* algorithm.')
  hasher = f'sha{algmatch.group("shabits")}'

  # Determine key based on raw PKCS1v1.5 inputs.
  msg1 = f'{h1}.{p1}'.encode('ascii')
  msg2 = f'{h2}.{p2}'.encode('ascii')
  sig1 = urlbase64_decode(s1)
  sig2 = urlbase64_decode(s2)
  pubkey = find_pkcs1v15_pubkey(msg1, sig1, msg2, sig2, hasher, exponent)

  if not pubkey:
    raise Exception('Failed to compute public key.')

  return jwk_encode_rsakey(*pubkey)

def main():
  parser = ArgumentParser(
    description='This script attempts to find out the RSA public key used to sign two different JWS\'s. ' \
               +'Works for the RS256, RS384 and RS512 algorithms. May take around a minute to compute.')
  parser.add_argument('-e', type=int, help=f'RSA public key exponent. If omitted, the most common values will be tried.')
  parser.add_argument('-f', action='store_true', help='Treat jws1 and jws2 as file names instead of JWS strings directly passed as arguments.')
  parser.add_argument('-o', type=FileType('w'), metavar='JWK_FILE', default=sys.stdout, help='Output file for the computed public key, in JWK format. Default is stdout.')
  parser.add_argument('jws1', help='First JWS object.')
  parser.add_argument('jws2', help='Second JWS object, signed by the same key but with a different payload.')
  args = parser.parse_args()
  
  if args.f:
    with open(args.jws1, 'r') as file1, open(args.jws2, 'r') as file2:
      jws1 = file1.read()
      jws2 = file2.read()
  else:
    jws1 = args.jws1
    jws2 = args.jws2

  print(f'Computing public key. This may take a minute...', file=sys.stderr)
  try:
    print(find_jws_pubkey(jws1, jws2, args.e), file=args.o)
  except Exception as ex:
    print(f'Error: {ex}', file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
  main()

