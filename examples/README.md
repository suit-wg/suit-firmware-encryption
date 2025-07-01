# SUIT Encrypted Payloads example binaries

Before each PR merged, examples are validated automatically.

## Requirements

- make
- curl
- sed
- xxd
- python3 and pip
  - python-cwt: `pip install 'cwt>=3.0.0'`
- ruby and gem
  - cbor-diag: `gem install cbor-diag`
  - cddl: `gem install cddl`

## Validating Examples
These are checked:
- Do each hex and diag pair of example SUIT_Encryption_Info match?
- Does each example SUIT_Encryption_Info match the CDDL defined in this document?
- Does each example SUIT Manifest match the CDDL of SUIT Manifest + Encrypted Payload + Multiple Trust Domains?
- Can we decrypt the expected plaintext payload from each example SUIT_Encryption_Info?

```
$ make validate
```
