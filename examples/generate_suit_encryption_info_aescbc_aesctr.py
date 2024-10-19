#!/usr/bin/env python3

import base64
import sys
import subprocess
from cwt import COSE, COSEMessage, COSEKey, Recipient

plaintext = b"This is a real firmware image."

############################################
print("# AES-CBC Examples")
a128cbc_key = COSEKey.from_symmetric_key(bytes.fromhex("627FCF0EA82C967D5ED8981EB325F303"), alg="A128CBC")
print(f"AES-CBC key = {{'kty': {a128cbc_key.kty}, 'k': h'{a128cbc_key.key.hex().upper()}'}}")
a128cbc_iv = bytes.fromhex("93702C81590F845D9EC866CCAC767BD1")
print(f"IV for AES-CBC = {a128cbc_iv.hex().upper()}")
print()

print("## Example 3: A128KW + A128CBC")
a128kw_key = COSEKey.from_symmetric_key("a" * 16, alg="A128KW", kid="kid-1")
print(f"AES-KW key = {{'kty': {a128kw_key.kty}, 'k': h'{a128kw_key.key.hex().upper()}'}}")
r = Recipient.new(unprotected={"alg": "A128KW", "kid": a128kw_key.kid}, sender_key=a128kw_key)
sender = COSE.new()
encoded = sender.encode_and_encrypt(
    plaintext,
    a128cbc_key,
    protected={},
    unprotected={
        "alg": "A128CBC",
        "iv": a128cbc_iv
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
print("## Example 4: ECDH-ES+A128KW + A128CBC")

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

kdf_context_a128cbc = {
    "alg": "A128KW",
    "supp_pub": {
        "key_data_length": 128,
        "protected": {"alg": "ECDH-ES+A128KW"},
        "other": "SUIT Payload Encryption",
    }
}

# The sender side:
r = Recipient.new(
    protected={"alg": "ECDH-ES+A128KW"},
    sender_key=COSEKey.from_jwk(sender_private_key_jwk),
    recipient_key=COSEKey.from_jwk(receiver_public_key_jwk),
    context=kdf_context_a128cbc
)
sender = COSE.new()
encoded = sender.encode(
    plaintext,
    key=a128cbc_key,
    protected={},
    unprotected={
        "alg": "A128CBC",
        "iv": a128cbc_iv
    },
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
decrypted_payload = recipient.decode(
    encoded,
    keys=COSEKey.from_jwk(sender_private_key_jwk),
    context=kdf_context_a128cbc
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

############################################
print("# AES-CTR Examples")
a128ctr_key = COSEKey.from_symmetric_key(bytes.fromhex("261DE6165070FB8951EC5D7B92A065FE"), alg="A128CTR")
print(f"AES-CTR key = {{'kty': {a128ctr_key.kty}, 'k': h'{a128ctr_key.key.hex().upper()}'}}")
a128ctr_iv = bytes.fromhex("DAE613B2E0DC55F4322BE38BDBA9DC68")
print(f"IV for AES-CTR = {a128ctr_iv.hex().upper()}")
print()

print("## Example 5: A128KW + A128CTR")
a128kw_key = COSEKey.from_symmetric_key("a" * 16, alg="A128KW", kid="kid-1")
print(f"AES-KW key = {{'kty': {a128kw_key.kty}, 'k': h'{a128kw_key.key.hex().upper()}'}}")
r = Recipient.new(unprotected={"alg": "A128KW", "kid": a128kw_key.kid}, sender_key=a128kw_key)
sender = COSE.new()
encoded = sender.encode_and_encrypt(
    plaintext,
    key=a128ctr_key,
    protected={},
    unprotected={
        "alg": "A128CTR",
        "iv": a128ctr_iv
    },
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
decrypted_payload = recipient.decode(encoded, keys=[a128kw_key])
assert plaintext == decrypted_payload

output = subprocess.check_output(f"echo {encoded.hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"COSE_Encrypt: {output}")
print(f"in hex: {encoded.hex().upper()}")
print(f"Decrypted payload: {decrypted_payload}")

suit_encryption_info, detached_payload = COSEMessage.loads(encoded).detach_payload()
output = subprocess.check_output(f"echo {suit_encryption_info.dumps().hex().upper()} | pretty2diag.rb -e", shell=True).decode(sys.stdout.encoding).rstrip("\n")
print(f"SUIT_Encryption_Info: {output}")
print(f"in hex: {suit_encryption_info.dumps().hex().upper()}")
print(f"Detached Payload: {detached_payload.hex().upper()}")
print()

############################################
print("## Example 6: ECDH-ES+A128KW + A128CTR")

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

kdf_context_a128ctr = {
    "alg": "A128KW",
    "supp_pub": {
        "key_data_length": 128,
        "protected": {"alg": "ECDH-ES+A128KW"},
        "other": "SUIT Payload Encryption",
    }
}

# The sender side:
r = Recipient.new(
    protected={"alg": "ECDH-ES+A128KW"},
    sender_key=COSEKey.from_jwk(sender_private_key_jwk),
    recipient_key=COSEKey.from_jwk(receiver_public_key_jwk),
    context=kdf_context_a128ctr
)
sender = COSE.new()
encoded = sender.encode(
    plaintext,
    key=a128ctr_key,
    protected={},
    unprotected={
        "alg": "A128CTR",
        "iv": a128ctr_iv
    },
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
decrypted_payload = recipient.decode(
    encoded,
    keys=COSEKey.from_jwk(sender_private_key_jwk),
    context=kdf_context_a128ctr
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
