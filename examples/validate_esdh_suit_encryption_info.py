#!/usr/bin/env python3

import base64
from cbor2 import dumps
from cwt import COSE, COSEKey

# See Section 6.2.5 Example (ECDH-ES + AES-KW)
# https://datatracker.ietf.org/doc/html/draft-ietf-suit-firmware-encryption#name-example-2
print("Example 2: ECDH-ES + AES-KW")
receiver_private_key_jwk = {
    "kty": "EC2",
    "crv": "P-256",
    "x": '5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3',
    "y": '9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B',
    "d": '60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3',
    "key_ops": ["deriveKey"],
    "alg": "ECDH-ES+A128KW",
    "kid": "kid-2",
}
print(f"Receiver's Private Key: {receiver_private_key_jwk}")
for key in ["x", "y", "d"]:
    receiver_private_key_jwk[key] = base64.b64encode(bytes.fromhex(receiver_private_key_jwk[key])).decode()

with open("./encrypted-payload-es-ecdh.hex", "r") as f:
    encrypted_payload_hex = ''.join(f.read().splitlines())
print(f"Encrypted Payload: {encrypted_payload_hex}")
with open("./suit-encryption-info-es-ecdh.hex", "r") as f:
    suit_encryption_info_hex = ''.join(f.read().splitlines())
print(f"SUIT_Encryption_Info: {suit_encryption_info_hex}")

# Decrypt the Encrypted Payload using SUIT_Encryption_Info
# NOTE: python-cwt does not support detached content feature used in SUIT Encrypted Payloads
# With this feature, the payload is encoded with `null` (0xF6 in hex)
# and can be replaced with bstr wrapped encrypted_payload.

# 1. Generate bstr wrapped encrypted_payload in hex
encrypted_payload_bytes = bytes.fromhex(encrypted_payload_hex)
encrypted_payload_bstr_hex = dumps(encrypted_payload_bytes).hex().upper()

# 2. Replace `null` (0xF6 in hex) by bstr wrapped encrypted_payload
# NOTE: Skip 13 bytes (26 characters) of protected and unprotected headers
index = suit_encryption_info_hex.find("F6", 26)
assert index >= 0
cose_encrypt_hex = suit_encryption_info_hex[0:index] + encrypted_payload_bstr_hex + suit_encryption_info_hex[index + 2:]

print(f"\nConcatenated COSE_Encrypt (non detached content): {cose_encrypt_hex}")
cose_encrypt_bytes = bytes.fromhex(cose_encrypt_hex)

private_key = COSEKey.from_jwk(receiver_private_key_jwk)

ctx = COSE.new()
context = {
    "alg": "A128KW",
    "supp_pub": {
        "key_data_length": 128,
        "protected": {1: -29}, # "alg": "ECDH-ES+A128KW"
        "other": "SUIT Payload Encryption",
    },
}
result = ctx.decode(cose_encrypt_bytes, keys=[private_key], context=context)
print(f"\nDecrypted Payload: {result}")
assert result == b'This is a real firmware image.'
print("Successfully decrypted")
