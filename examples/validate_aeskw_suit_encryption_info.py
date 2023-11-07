#!/usr/bin/env python3

import base64
from cwt import COSE, COSEKey

expected_plaintext_payload = b'This is a real firmware image.'

# See Section 6.1.4 Example (AES-KW)
# https://datatracker.ietf.org/doc/html/draft-ietf-suit-firmware-encryption#name-example
print("Example 1: AES-KW")

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
filename_hex_suit_encryption_info = "suit-encryption-info-aes-kw-aes-gcm.hex"
with open(filename_hex_suit_encryption_info, "r") as f:
    suit_encryption_info_hex = ''.join(f.read().splitlines())
print(f"SUIT_Encryption_Info: {suit_encryption_info_hex}")
suit_encryption_info_bytes = bytes.fromhex(suit_encryption_info_hex)

filename_diag_suit_encryption_info = "suit-encryption-info-es-ecdh-aes-gcm.diag"
with open(filename_diag_suit_encryption_info, "r") as f:
    print(f.read())

filename_encrypted_payload = "encrypted-payload-aes-kw-aes-gcm.hex"
with open(filename_encrypted_payload, "r") as f:
    encrypted_payload_hex = ''.join(f.read().splitlines())
print(f"Encrypted Payload: {encrypted_payload_hex}")
encrypted_payload_bytes = bytes.fromhex(encrypted_payload_hex)

# 2. Decrypt the Encrypted Payload using SUIT_Encryption_Info
ctx = COSE.new()
result = ctx.decode(suit_encryption_info_bytes, keys=[secret_key], detached_payload=encrypted_payload_bytes)
print(f"\nDecrypted Payload: {result}")
assert result == expected_plaintext_payload
print("Successfully decrypted")
