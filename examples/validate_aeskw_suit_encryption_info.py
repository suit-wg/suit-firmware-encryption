#!/usr/bin/env python3

import sys
import base64
from cwt import COSE, COSEKey

if len(sys.argv) != 3:
    print(f"{sys.argv[0]} [hex-encryption-info] [hex-encrypted-payload]")

filename_hex_suit_encryption_info = sys.argv[1]
filename_hex_encrypted_payload = sys.argv[2]
filename_diag_suit_encryption_info = filename_hex_suit_encryption_info.replace(".hex", ".diag")

expected_plaintext_payload = b'This is a real firmware image.'

# 0. Load the Secret Key
secret_key_jwk = {
    "kty": "Symmetric",
    "k": "61" * 16, # 0x61 = 'a'
    "alg": "A128KW",
    "kid": "kid-1",
}
print(f"Secret COSE_Key: {secret_key_jwk}")
for key in ["k"]:
    secret_key_jwk[key] = base64.b64encode(bytes.fromhex(secret_key_jwk[key])).decode()
secret_key = COSEKey.from_jwk(secret_key_jwk)
print()

# 1. Load SUIT_Encryption_Info and the detached Encrypted Payload
with open(filename_hex_suit_encryption_info, "r") as f:
    suit_encryption_info_hex = ''.join(f.read().splitlines())
print(f"SUIT_Encryption_Info:\n{suit_encryption_info_hex}")
suit_encryption_info_bytes = bytes.fromhex(suit_encryption_info_hex)

with open(filename_diag_suit_encryption_info, "r") as f:
    print(f.read())

with open(filename_hex_encrypted_payload, "r") as f:
    encrypted_payload_hex = ''.join(f.read().splitlines())
print(f"Encrypted Payload:\n{encrypted_payload_hex}")
encrypted_payload_bytes = bytes.fromhex(encrypted_payload_hex)

# 2. Decrypt the Encrypted Payload using SUIT_Encryption_Info
ctx = COSE.new()
result = ctx.decode(suit_encryption_info_bytes, keys=[secret_key], detached_payload=encrypted_payload_bytes)
print(f"\nDecrypted Payload: {result}")
assert result == expected_plaintext_payload
print("Successfully decrypted")
