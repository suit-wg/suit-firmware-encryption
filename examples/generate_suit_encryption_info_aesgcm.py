#!/usr/bin/env python3

import base64
import sys
import subprocess
from cwt import COSE, COSEMessage, COSEKey, Recipient

plaintext = b"This is a real firmware image."

############################################
print("# AES-GCM Examples")
a128gcm_key = COSEKey.from_symmetric_key(bytes.fromhex("15F785B5C931414411B4B71373A9C0F7"), alg="A128GCM")
print(f"AES-GCM key = {{'kty': {a128gcm_key.kty}, 'k': h'{a128gcm_key.key.hex().upper()}'}}\n")

print("## Example 1: A128KW + A128GCM")
a128kw_key = COSEKey.from_symmetric_key("a" * 16, alg="A128KW", kid="kid-1")
print(f"AES-KW key = {{'kty': {a128kw_key.kty}, 'k': h'{a128kw_key.key.hex().upper()}'}}")
r = Recipient.new(unprotected={"alg": "A128KW", "kid": a128kw_key.kid}, sender_key=a128kw_key)
sender = COSE.new()
encoded = sender.encode_and_encrypt(
    plaintext,
    a128gcm_key,
    protected={
        "alg": "A128GCM"
    },
    unprotected={
        "iv": bytes.fromhex("F14AAB9D81D51F7AD943FE87AF4F70CD")
    },
    recipients=[r],
)
print(encoded.hex().upper())

# The recipient side:
recipient = COSE.new()
decrypted_payload = recipient.decode(encoded, keys=[a128kw_key])
assert plaintext == decrypted_payload

output = subprocess.check_output(f"echo {encoded.hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"COSE_Encrypt: {output}")
print(f"Decrypted payload: {decrypted_payload}")

suit_encryption_info, detached_payload = COSEMessage.loads(encoded).detach_payload()
output = subprocess.check_output(f"echo {suit_encryption_info.dumps().hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"SUIT_Encryption_Info: {output}")
print(f"in hex: {suit_encryption_info.dumps().hex().upper()}")
print(f"Detached Payload: {detached_payload.hex().upper()}")
print()

############################################
print("## Example 2: ECDH-ES+A128KW + A128GCM")

sender_private_key_jwk = {
    "kty": "EC2",
    "crv": "P-256",
    "x": '8496811AAE0BAAABD26157189EECDA26BEAA8BF11B6F3FE6E2B5659C85DBC0AD',
    "y": '3B1F2A4B6C098131C0A36DACD1D78BD381DCDFB09C052DB33991DB7338B4A896',
    "d": '0296588D909418B339D150420A3612B57FB4F631A69F224FAE90CB4F3FE18973',
    "alg": "ECDH-ES+A128KW",
    "kid": "kid-2",
}
print(f"Sender's Private Key: {sender_private_key_jwk}")

receiver_private_key_jwk = {
    "kty": "EC2",
    "crv": "P-256",
    "x": '5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3',
    "y": '9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B',
    "d": '60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3',
}
print(f"Receiver's Private Key: {receiver_private_key_jwk}")

receiver_public_key_jwk = dict(
    (k, receiver_private_key_jwk[k]) for k in ["kty", "crv", "x", "y"]
)
print(f"Receiver's Public Key: {receiver_public_key_jwk}")

for key in ["x", "y", "d"]:
    sender_private_key_jwk[key] = base64.b64encode(bytes.fromhex(receiver_private_key_jwk[key])).decode()

for key in ["x", "y", "d"]:
    receiver_private_key_jwk[key] = base64.b64encode(bytes.fromhex(receiver_private_key_jwk[key])).decode()

for key in ["x", "y"]:
    receiver_public_key_jwk[key] = base64.b64encode(bytes.fromhex(receiver_public_key_jwk[key])).decode()

kdf_context_a128gcm = {
    "alg": "A128KW",
    "supp_pub": {
        "key_data_length": 128,
        "protected": {"alg": "ECDH-ES+A128KW"},
        "other": "SUIT Payload Encryption",
    }
}

# The sender side:
r = Recipient.new(
    protected={},
    unprotected={"alg": "ECDH-ES+A128KW"},
    sender_key=COSEKey.from_jwk(sender_private_key_jwk),
    recipient_key=COSEKey.from_jwk(receiver_public_key_jwk),
    context=kdf_context_a128gcm
)
sender = COSE.new()
encoded = sender.encode(
    plaintext,
    key=a128gcm_key,
    protected={
        "alg": "A128GCM"
    },
    unprotected={
        "iv": bytes.fromhex("F14AAB9D81D51F7AD943FE87AF4F70CD")
    },
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
decrypted_payload = recipient.decode(
    encoded,
    keys=COSEKey.from_jwk(sender_private_key_jwk),
    context=kdf_context_a128gcm
)
assert plaintext == decrypted_payload

output = subprocess.check_output(f"echo {encoded.hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"COSE_Encrypt: {output}")
print(f"Decrypted payload: {decrypted_payload}")

suit_encryption_info, detached_payload = COSEMessage.loads(encoded).detach_payload()
output = subprocess.check_output(f"echo {suit_encryption_info.dumps().hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"SUIT_Encryption_Info: {output}")
print(f"in hex: {suit_encryption_info.dumps().hex().upper()}")
print(f"Detached Payload: {detached_payload.hex().upper()}")
print()
