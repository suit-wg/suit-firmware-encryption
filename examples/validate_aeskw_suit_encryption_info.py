#!/usr/bin/env python3

import base64
from cbor2 import dumps
from cwt import COSE, COSEKey

print("Example 1: AES-KW")
secret_key_jwk = {
    "kty": "Symmetric",
    "k": "61" * 16, # 0x61 = 'a'
    "alg": "A128KW",
    "kid": "kid-1",
}
print(f"Secret COSE_Key: {secret_key_jwk}")
for key in ["k"]:
    secret_key_jwk[key] = base64.b64encode(bytes.fromhex(secret_key_jwk[key])).decode()
with open("./encrypted-payload-aes-kw.hex", "r") as f:
    encrypted_payload_hex = ''.join(f.read().splitlines())
print(f"Encrypted Payload: {encrypted_payload_hex}")
with open("./suit-encryption-info-aes-kw.hex", "r") as f:
    suit_encryption_info_hex = ''.join(f.read().splitlines())
print(f"SUIT_Encryption_Info: {suit_encryption_info_hex}")

# Decrypt the Encrypted Payload using SUIT_Encryption_Info
# NOTE: python-cwt does not support detached content feature used in SUIT Encrypted Payloads
# With this feature, the payload is encoded with `null` (0xF6 in hex)
# and can be replaced with bstr wrapped encrypted_payload.

# 1. Generate bstr wrapped encrypted_payload in hex
encrypted_payload_bytes = bytes.fromhex(encrypted_payload_hex)
encrypted_payload_bstr_hex = dumps(encrypted_payload_bytes).hex()

# 2. Replace `null` (0xF6 in hex) by bstr wrapped encrypted_payload
# NOTE: Skip 13 bytes (26 characters) protected and unprotected headers
index = suit_encryption_info_hex.find("F6", 26)
assert index >= 0
cose_encrypt_hex = suit_encryption_info_hex[0:index] + encrypted_payload_bstr_hex + suit_encryption_info_hex[index + 2:]

print(f"\nGenerated COSE_Encrypt: {cose_encrypt_hex}")
cose_encrypt_bytes = bytes.fromhex(cose_encrypt_hex)

secret_key = COSEKey.from_jwk(secret_key_jwk)

ctx = COSE.new()
result = ctx.decode(cose_encrypt_bytes, keys=[secret_key])
print(f"\nDecrypted Payload: {result}")
assert result == b'This is a real firmware image.'
