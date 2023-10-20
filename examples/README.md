# SUIT Encrypted Payloads example binaries

## Validating Examples
These are checked:
- Does each example SUIT_Encryption_Info match the CDDL defined in this document?
- Does each example SUIT Manifest match the CDDL of SUIT Manifest + Encrypted Payload + Multiple Trust Domains?
- Can we decrypt the expected plaintext payload from each example SUIT_Encryption_Info?

```
$ make validate
```
