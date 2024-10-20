---
title: Encrypted Payloads in SUIT Manifests
abbrev: Encrypted Payloads in SUIT Manifests
docname: draft-ietf-suit-firmware-encryption-21
category: std

ipr: trust200902
area: Security
workgroup: SUIT
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
  toc_levels: 4

author:
 -
       name: Hannes Tschofenig
       org: University of Applied Sciences Bonn-Rhein-Sieg
       abbrev: H-BRS
       email: Hannes.Tschofenig@gmx.net

 -
       ins: R. Housley
       name: Russ Housley
       organization: Vigil Security, LLC
       abbrev: Vigil Security
       email: housley@vigilsec.com

 -
      ins: B. Moran
      name: Brendan Moran
      organization: Arm Limited
      email: Brendan.Moran@arm.com

 -
      ins: D. Brown
      name: David Brown
      organization: Linaro
      email: david.brown@linaro.org

 -
      ins: K. Takayama
      name: Ken Takayama
      organization: SECOM CO., LTD.
      email: ken.takayama.ietf@gmail.com

normative:
  RFC2119:
  RFC3394:
  RFC9052:
  RFC9053:
  RFC8174:
  I-D.ietf-suit-manifest:
  RFC9459:
  I-D.ietf-suit-trust-domains:

informative:
  RFC9019:
  RFC9124:
  RFC8937:
  RFC5652:
  RFC5280:
  RFC5869:
  iana-suit:
    author:
      org: Internet Assigned Numbers Authority
    title: IANA SUIT Manifest Registry
    date: 2023
    target: TBD
  ROP:
    author:
      org: Wikipedia
    title: Return-Oriented Programming
    date: 06.03.2023
    target: https://en.wikipedia.org/wiki/Return-oriented_programming
  SP800-56:
    author:
      org: NIST
    title: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography, NIST Special Publication 800-56A Revision 3
    date: April 2018
    target: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf

--- abstract

This document specifies techniques for encrypting software, firmware,
machine learning models, and personalization data by utilizing the IETF
SUIT manifest. Key agreement is provided by ephemeral-static (ES)
Diffie-Hellman (DH) and AES Key Wrap (AES-KW). ES-DH uses public key
cryptography while AES-KW uses a pre-shared key. Encryption of the
plaintext is accomplished with conventional symmetric key cryptography.

--- middle

#  Introduction

Vulnerabilities with Internet of Things (IoT) devices have raised the
need for a reliable and secure firmware update mechanism that is also
suitable for constrained devices. To protect firmware images, the SUIT manifest
format was developed {{I-D.ietf-suit-manifest}}. It provides a bundle of
metadata, including where to find the payload, the devices to which it
applies and a security wrapper.

{{RFC9124}} details the information that has to be provided by the SUIT
manifest format. In addition to offering protection against modification,
via a digital signature or a message authentication code,
confidentiality may also be afforded.

Encryption prevents third parties, including attackers, from gaining
access to the payload. Attackers typically need intimate knowledge
of a binary, such as a firmware image, to mount their attacks.
For example, return-oriented programming (ROP) {{ROP}} requires access
to the binary and encryption makes it much more difficult to write exploits.
Beside confidentiality of the binary, confidentiality of the sources
(e.g. in case of open source software) may be required as well to prevent
reverse engineering and/or reproduction of the binary firmware.

While the original motivating use case of this document was firmware
encryption, the use of SUIT manifests has been extended to other use cases
requiring integrity and confidentiality protection, such as:

- software packages,
- personalization data,
- configuration data, and
- machine learning models.
 
Hence, we use the term payload to generically refer to all those objects.

The payload is encrypted using a symmetric content encryption
key, which can be established using a variety of mechanisms; this
document defines two content key distribution methods for use with
the IETF SUIT manifest, namely:

- Ephemeral-Static (ES) Diffie-Hellman (DH), and
- AES Key Wrap (AES-KW).

The former method relies on asymmetric key cryptography while the
latter uses symmetric key cryptography.

Our design aims to reduce the number of content key distribution methods
for use with payload encryption and thereby increase interoperability
between different SUIT manifest parser implementations.

The goal of this specification is to protect payloads during end-to-end
transport, and at rest when stored on a device. Constrained devices often
make use of XIP, which is a method of executing code
directly from flash memory rather than copying it into RAM. Since many of
these devices today do not offer hardware-based, on-the-fly decryption of
code stored in flash memory, it may be necessary to decrypt and store
firmware images in on-chip flash before code can be executed. We do, however,
expect that hardware-based, on-the-fly decryption will become more common in
the future, which will improve confidentiality at rest.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document assumes familiarity with the IETF SUIT manifest {{I-D.ietf-suit-manifest}},
the SUIT information model {{RFC9124}}, and the SUIT architecture {{RFC9019}}.

The following abbreviations are used in this document:

* Key Wrap (KW), defined in {{RFC3394}} (for use with AES)
* Key-Encryption Key (KEK) {{RFC3394}}
* Content-Encryption Key (CEK) {{RFC5652}}
* Ephemeral-Static (ES) Diffie-Hellman (DH) {{RFC9052}}
* Authenticated Encryption with Associated Data (AEAD)
* Execute in Place (XIP)

The terms sender and recipient have the following meaning:

* Sender: Entity that sends an encrypted payload.
* Recipient: Entity that receives an encrypted payload.

Additionally, we introduce the term "distribution system" (or distributor)
to refer to an entity that knows the recipients of payloads. It is important
to note that the distribution system is far more than a file server. For
use of encryption, the distribution system either knows the public key
of the recipient (for ES-DH), or the KEK (for AES-KW).

The author, which is responsible for creating the payload, does not
know the recipients. The authors may, for example, be a developer building
a firmware image.

The author and the distribution system are logical roles. In some
deployments these roles are separated in different physical entities
and in others they are co-located.

# Architecture {#arch}

{{RFC9019}} describes the architecture for distributing payloads and
manifests from an author to devices. It does, however, not detail the
use of payload encryption. This document enhances the architecture to
support encryption and {{arch-fig}} shows it graphically.

To encrypt a payload it is necessary to know the recipient.
For AES-KW, the KEK needs to be known and, in case of ES-DH, the sender needs
to be in possession of the public key of the recipient. The public key and
parameters may be in the recipient's X.509 certificate {{RFC5280}}. For
authentication of the sender and for integrity protection the recipients
must be provisioned with a trust anchor when a manifest is protected using
a digital signature. When a MAC is used to protect the manifest then a
symmetric key must be shared by the recipient and the sender.

With encryption, the author cannot just create a manifest for the payload
and sign it, since it typically does not know the recipients. Hence, the
author has to collaborate with the distribution system. The varying degree
of collaboration is discussed below.

~~~ aasvg
 +----------+
 |  Device  |                              +----------+
 |    1     |<--+                          |  Author  |
 |          |   |                          +----------+
 +----------+   |                               |
                |                               | Payload +
                |                               | Manifest
                |                               v
 +----------+   |                        +--------------+
 |  Device  |   |  Payload + Manifest    | Distribution |
 |    2     |<--+------------------------|    System    |
 |          |   |                        +--------------+
 +----------+   |
                |
      ...       |
                |
 +----------+   |
 |  Device  |   |
 |    n     |<--+
 |          |
 +----------+
~~~
{: #arch-fig title="Architecture for the distribution of Encrypted Payloads."}

The author has several deployment options, namely:

* The author, as the sender, obtains information about the recipients
  and their keys from the distribution system. There are proprietary as well as
  standardized device management solutions available providing this functionality,
  as discussed in {{RFC9019}}. Then, it performs the necessary
  steps to encrypt the payload. As a last step it creates one or more manifests.
  The device(s) perform decryption and act as recipients.

* The author treats the distribution system as the initial recipient. The
  author typically uses REST APIs or web user interfaces to interact with the
  distribution system. Then, the distribution system decrypts and re-encrypts the
  payload for consumption by the device (or the devices). Delegating the task of
  re-encrypting the payload to the distribution system offers flexibility when the
  number of devices that need to receive encrypted payloads changes dynamically
  or when updates to KEKs or recipient public keys are necessary. As a downside,
  the author needs to trust the distribution system with performing the
  re-encryption of the payload.

If the author delegates encryption rights to the distributor two models are possible:

1. The distributor replaces the COSE_Encrypt in the manifest and then signs the
manifest again. However, the COSE_Encrypt structure is contained within a signed
container, which presents a problem: replacing the COSE_Encrypt with a new one
will cause the digest of the manifest to change, thereby changing the signature.
This means that the distributor must be able to sign the new manifest. If this
is the case, then the distributor gains the ability to construct and sign
manifests, which allows the distributor the authority to sign code, effectively
presenting the distributor with full control over the recipient. Because
distributors typically perform their re-encryption online in order to handle
a large number of devices in a timely fashion, it is not possible to air-gap
the distributor's signing operations. This impacts the recommendations in
{{Section 4.3.17 of RFC9124}}. This model nevertheless represent the current
state of firmware updates for IoT devices.

2. The distributor uses a two-layer manifest system. More precisely, the distributor
constructs a new manifest that overrides the COSE_Encrypt using the dependency
system defined in {{I-D.ietf-suit-trust-domains}}. This incurs additional
overhead: one additional signature verification and one additional manifest,
as well as the additional machinery in the recipient needed for dependency
processing. This extra complexity offers extra security.

These two models also present different threat profiles for the distributor.
If the distributor only has encryption rights, then an attacker who breaches
the distributor can only mount a limited attack: they can encrypt a modified
binary, but the recipients will identify the attack as soon as they perform
the required image digest check and revert back to a correct image immediately.

It is RECOMMENDED that distributors implement the two-layer manifest
approach in order to distribute content encryption keys without requiring
re-signing of the manifest, despite the increase in complexity and greater
number of signature verifications that this imposes on the recipient.

# Encryption Extensions {#parameters}

This specification introduces a new extension to the SUIT_Parameters structure.

The SUIT_Encryption_Info structure (called suit-parameter-encryption-info in
{{parameter-fig}}) contains the content key distribution information. The
content of the SUIT_Encryption_Info structure is explained in {{AES-KW}}
(for AES-KW) and in {{ES-DH}} (for ES-DH).

Once a CEK is available, the steps described in {{content-enc}} are applicable.
These steps apply to both content key distribution methods described in this
section.

The SUIT_Encryption_Info structure is either carried inside the
suit-directive-override-parameters or the suit-directive-set-parameters
parameters used in the "Directive Write" and "Directive Copy" directives.
An implementation claiming conformance with this specification
must implement support for these two parameters. Since a device will
typically only support one of the content key distribution methods,
the distribution system needs to know which of two specified methods
is supported. Mandating only a single content key distribution
method for a constrained device also reduces the code size.

~~~
SUIT_Parameters //= (suit-parameter-encryption-info
    => bstr .cbor SUIT_Encryption_Info)

suit-parameter-encryption-info = TBD19
~~~
{: #parameter-fig title="CDDL of the SUIT_Parameters Extension."}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

# Extended Directives

This specification extends these directives:

- Directive Write (suit-directive-write) to decrypt the content specified by
suit-parameter-content with suit-parameter-encryption-info.
- Directive Copy (suit-directive-copy) to decrypt the content of the component
specified by suit-parameter-source-component with suit-parameter-encryption-info.

Examples of the two directives are shown below. These example focus on the
essential aspects. A complete example for AES Key Wrap with the Fetch and Copy
Directives can be found in {{example-AES-KW-copy}}. An example illustrating
the Write Directive is shown in {{example-AES-KW-write}}.

{{encryption-info-consumed-with-write}} illustrates the Directive Write.
The encrypted payload specified with parameter-content, namely
h'EA1...CED' in the example, is decrypted using the SUIT_Encryption_Info
structure referred to by parameter-encryption-info, i.e., h'D86...1F0'.
The resulting plaintext payload is stored into component #0.

~~~
/ directive-override-parameters / 20, {
  / parameter-content / 18: h'EA1...CED',
  / parameter-encryption-info / TBD19: h'D86...1F0'
},
/ directive-write / 18, 15
~~~
{: #encryption-info-consumed-with-write title="Example showing the extended suit-directive-write."}

RFC Editor's Note (TBD19): The value for the parameter-encryption-info
parameter is set to 19, as the proposed value.

{{encryption-info-consumed-with-copy}} illustrates the Directive Copy.
In this example the encrypted payload is found at the URI indicated
by the parameter-uri, i.e. "http://example.com/encrypted.bin". The
encrypted payload will be downloaded and stored in component #1.
Then, the information in the SUIT_Encryption_Info structure referred
to by parameter-encryption-info, i.e. h'D86...1F0', will be used to
decrypt the content in component #1 and the resulting plaintext
payload will be stored into component #0.

~~~
/ directive-set-component-index / 12, 1,
/ directive-override-parameters / 20, {
  / parameter-uri / 21: "http://example.com/encrypted.bin",
},
/ directive-fetch / 21, 15,
/ directive-set-component-index / 12, 0,
/ directive-override-parameters / 20, {
  / parameter-encryption-info / TBD19: h'D86...1F0',
  / parameter-source-component / 22: 1
},
/ directive-copy / 22, 15
~~~
{: #encryption-info-consumed-with-copy title="Example showing the extended suit-directive-copy."}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

The payload to be encrypted may be detached and, in that case, it is
not covered by the digital signature or the MAC protecting the manifest.
(To be more precise, the suit-authentication-wrapper found in the envelope
contains a digest of the manifest in the SUIT Digest Container.) 

The lack of authentication and integrity protection of the payload is
particularly a concern when a cipher without integrity protection is
used.

To provide authentication and integrity protection of the payload
in the detached payload case a SUIT Digest Container with the hash
of the encrypted and/or plaintext payload MUST be included in the
manifest. See suit-parameter-image-digest parameter in {{Section
8.4.8.6 of I-D.ietf-suit-manifest}}.

Once a CEK is available, the steps described in {{content-enc}} are applicable.
These steps apply to both content key distribution methods.

# Content Key Distribution

The sub-sections below describe two content key distribution methods,
namely AES Key Wrap (AES-KW) and Ephemeral-Static Diffie-Hellman (ES-DH).
Many other methods are specified in the literature, and are even supported
by COSE. AES-KW and ES-DH cover the popular methods used in the market
today and they were selected due to their maturity, different
security properties, and because of their interoperability properties.

The two content key distribution methods require the CEKs to be
randomly generated. The guidelines for random number generation
in {{RFC8937}} MUST be followed.

When an encrypted payload is sent to multiple recipients, there
are different deployment options. To explain these options we use the
following notation:

~~~
   - KEK[R1, S] refers to a KEK shared between recipient R1 and
     the sender S.
   - CEK[R1, S] refers to a CEK shared between R1 and S.
   - CEK[*, S] or KEK[*, S] are used when a single CEK or a single
     KEK is shared with all authorized recipients by a given sender
     S in a certain context.
   - ENC(plaintext, k) refers to the encryption of plaintext with
     a key k.
~~~

## Content Key Distribution with AES Key Wrap {#AES-KW}

### Introduction

The AES Key Wrap (AES-KW) algorithm is described in {{RFC3394}}, and
can be used to encrypt a randomly generated content-encryption key (CEK)
with a pre-shared key-encryption key (KEK). The COSE conventions for using
AES-KW are specified in {{Section 8.5.2 of RFC9052}} and in {{Section 6.2.1 of
RFC9053}}. The encrypted CEK is carried in the COSE\_recipient structure
alongside the information needed for AES-KW. The COSE\_recipient structure,
which is a substructure of the COSE\_Encrypt structure, contains the CEK
encrypted by the KEK.

To provide high security for AES Key Wrap, it is important that the
KEK is of high entropy, and that implementations protect the KEK
from disclosure. Compromise of the KEK may result in the disclosure
of all data protected with that KEK, including binaries, and configuration data.

The COSE\_Encrypt structure conveys information for encrypting the payload,
which includes information like the algorithm and the IV, even though the
payload may not be embedded in the COSE_Encrypt.ciphertext if it is
conveyed as detached content.

### Deployment Options

There are three deployment options for use with AES Key Wrap for payload
encryption:

- If all recipients (typically of the same product family) share the same KEK,
a single COSE\_recipient structure contains the encrypted CEK. The sender executes
the following steps:

~~~
     1. Fetch KEK[*, S]
     2. Generate CEK
     3. ENC(CEK, KEK)
     4. ENC(payload, CEK)
~~~

This deployment option is strongly discouraged. An attacker gaining access to
the KEK will be able to encrypt and send payloads to all recipients configured
to use this KEK.

- If recipients have different KEKs, then multiple COSE\_recipient structures
are included but only a single CEK is used. Each COSE\_recipient structure
contains the CEK encrypted with the KEKs appropriate for a given recipient.
The benefit of this approach is that the payload is encrypted only once with
a CEK while there is no sharing of the KEK across recipients. Hence, authorized
recipients still use their individual KEK to decrypt the CEK and to subsequently
obtain the plaintext. The steps taken by the sender are:

~~~
    1.  Generate CEK
    2.  for i=1 to n
        {
    2a.    Fetch KEK[Ri, S]
    2b.    ENC(CEK, KEK[Ri, S])
        }
    3.  ENC(payload, CEK)
~~~

- The third option is to use different CEKs encrypted with KEKs of
authorized recipients. This approach is appropriate when no benefits can
be gained from encrypting and transmitting payloads only once. Assume there
are n recipients with their unique KEKs - KEK[R1, S], ..., KEK[Rn, S] and
unique CEKs. The sender needs to execute the following steps:

~~~
    1.  for i=1 to n
        {
    1a.    Fetch KEK[Ri, S]
    1b.    Generate CEK[Ri, S]
    1c.    ENC(CEK[Ri, S], KEK[Ri, S])
    1d.    ENC(payload, CEK[Ri, S])
    2.  }
~~~

### CDDL

The CDDL for the AES-KW binary is shown in {{cddl-aeskw}}.
empty_or_serialized_map and header_map are structures defined in {{RFC9052}}.

~~~
{::include cddls/aeskw.cddl}
~~~
{: #cddl-aeskw title="CDDL for AES-KW-based Content Key Distribution"}

Note that the AES-KW algorithm, as defined in {{Section 2.2.3.1 of RFC3394}},
does not have public parameters that vary on a per-invocation basis. Hence,
the protected header in the COSE_recipient structure is a byte string
of zero length.

## Content Key Distribution with Ephemeral-Static Diffie-Hellman {#ES-DH}

### Introduction

Ephemeral-Static Diffie-Hellman (ES-DH) is a scheme that provides public key
encryption given a recipient's public key. There are multiple variants
of this scheme; this document re-uses the variant specified in {{Section 8.5.5
of RFC9052}}.

The following two layer structure is used:

- Layer 0: Has a content encrypted with the CEK. The content may be detached.
- Layer 1: Uses the AES Key Wrap algorithm to encrypt the randomly generated
CEK with the KEK derived with ES-DH, whereby the resulting symmetric
key is fed into the HKDF-based key derivation function.

As a result, the two layers combine ES-DH with AES-KW and HKDF,
and it is called ECDH-ES + AES-KW.
An example is given in {{esdh-aesgcm-example}}.

There exists another version of ES-DH algorithm, namely ECDH-ES + HKDF, which
does not use AES Key Wrap. It is not specified in this document.

### Deployment Options

There are only two deployment options with this approach since we assume that
recipients are always configured with a device-unique public / private key pair.

- A sender wants to transmit a payload to multiple recipients and all recipients
receive the same encrypted payload, i.e. the same CEK is used to encrypt the payload.
One COSE\_recipient structure per recipient is used and it contains the
CEK encrypted with the KEK. To generate the KEK each COSE\_recipient structure
contains a COSE_recipient_inner structure to carry the sender's ephemeral key
and an identifier for the recipients public key.

The steps taken by the sender are:

~~~
    1.  Generate CEK
    2.  for i=1 to n
        {
    2a.     Generate KEK[Ri, S] using ES-DH
    2b.     ENC(CEK, KEK[Ri, S])
        }
    3.  ENC(payload,CEK)
~~~

- The alternative is to encrypt a payload with a different CEK for each
recipient. This results in n-manifests. This approach is useful when payloads contain
information unique to a device. The encryption operation then effectively becomes
ENC(payload_i, CEK[Ri, S]). Assume that KEK[R1, S],..., KEK[Rn, S] have been generated
for the different recipients using ES-DH. The following steps need to be made
by the sender:

~~~
    1.  for i=1 to n
        {
    1a.     Generate KEK[Ri, S] using ES-DH
    1b.     Generate CEK[Ri, S]
    1c.     ENC(CEK[Ri, S], KEK[Ri, S])
    1d.     ENC(payload, CEK[Ri, S])
        }
~~~

### CDDL

The CDDL for the ECDH-ES+AES-KW binary is shown in {{cddl-esdh}}.
Only the minimum number of parameters is shown. empty_or_serialized_map
and header_map are structures defined in {{RFC9052}}.

~~~
{::include cddls/esdh_aeskw.cddl}
~~~
{: #cddl-esdh title="CDDL for ES-DH-based Content Key Distribution"}

See {{content-enc}} for a description on how to encrypt the payload.

### Context Information Structure

The context information structure is used to ensure that the derived keying material
is "bound" to the context of the transaction. This specification re-uses the structure
defined in {{Section 5.2 of RFC9053}} and tailors it accordingly.

The following information elements are bound to the context:

* the protocol employing the key-derivation method,
* information about the utilized AES Key Wrap algorithm, and the key length.
* the protected header field, which contains the content key encryption algorithm.

The sender and recipient identities are left empty.

The following fields in {{cddl-context-info}} require an explanation:

- The COSE_KDF_Context.AlgorithmID field MUST contain the algorithm identifier
for AES Key Wrap algorithm utilized. This specification uses the following
values: A128KW (value -3), A192KW (value -4), or A256KW (value -5)

- The COSE_KDF_Context.SuppPubInfo.keyDataLength field MUST contain the key length
of the algorithm in the COSE_KDF_Context.AlgorithmID field expressed as the number
of bits. For A128KW the value is 128, for A192KW the value is 192, and for A256KW
the value 256.

- The COSE_KDF_Context.SuppPubInfo.other field captures the protocol in
which the ES-DH content key distribution algorithm is used and MUST be set to
the constant string "SUIT Payload Encryption".

- The COSE_KDF_Context.SuppPubInfo.protected field MUST contain the serialized
content of the recipient_header_map_esdh field, which contains (among other fields)
the identifier of the content key distribution method.

~~~ CDDL
{::include cddls/kdf-context.cddl}
~~~
{: #cddl-context-info title="CDDL for COSE_KDF_Context Structure"}

The HKDF-based key derivation function MAY contain a salt value,
as described in {{Section 5.1 of RFC9053}}. This optional value is used to
influence the key generation process. This specification does not mandate the
use of a salt value. If the salt is public and carried in the message, then
the "salt" algorithm header parameter MUST be used. The purpose of the salt
is to provide extra randomness in the KDF context. If the salt is sent
in the 'salt' algorithm header parameter, then the receiver MUST be able to
process the salt and MUST pass it into the key derivation function.
For more information about the salt, see {{RFC5869}} and NIST
SP800-56 {{SP800-56}}.

Profiles of this specification MAY specify an extended version of the
context information structure or MAY utilize a different context information
structure.

# Content Encryption {#content-enc}

This section summarizes the steps taken for content encryption, which
applies to both content key distribution methods.

For use with AEAD ciphers, such as AES-GCM and ChaCha20/Poly1305,
the COSE specification requires a consistent byte
stream for the authenticated data structure to be created. This structure
is shown in {{cddl-enc-aeskw}} and is defined in {{Section 5.3 of RFC9052}}.

~~~
 Enc_structure = [
   context : "Encrypt",
   protected : empty_or_serialized_map,
   external_aad : bstr
 ]
~~~
{: #cddl-enc-aeskw title="CDDL for Enc_structure Data Structure"}

This Enc_structure needs to be populated as follows:

- The protected field in the Enc_structure from {{cddl-enc-aeskw}} refers
to the content of the protected field from the COSE_Encrypt structure.

- The value of the external_aad MUST be set to a zero-length byte string,
i.e., h'' in diagnostic notation and encoded as 0x40.

Some ciphers provide confidentiality without integrity protection, such
as AES-CTR and AES-CBC (see {{RFC9459}}). For these ciphers the
Enc_structure, shown in {{cddl-enc-aeskw}}, cannot be used because
the Additional Authenticated Data (AAD) byte string is only consumable
by AEAD ciphers. Hence, the AAD structure is not supplied to the 
API of those ciphers and the protected header in the SUIT_Encryption_Info
structure MUST be a zero-length byte string.

AES-CTR and AES-CBC are discussed in separate sub-sections below and
{{aes-ctr-fig}} and {{aes-cbc-fig}} use the following abbreviations:

- Pi = Plaintext blocks
- Ci = Ciphertext blocks
- E = Encryption function
- k = Symmetric key
- ⊕ = XOR operation

## AES-GCM

### Introduction

AES-GCM is an AEAD cipher and provides confidentiality and integrity protection.

Examples in this section use the following parameters:

- Algorithm for payload encryption: AES-GCM-128
  - k: h'15F785B5C931414411B4B71373A9C0F7'
  - IV: h'F14AAB9D81D51F7AD943FE87AF4F70CD'
- Plaintext: "This is a real firmware image."
  - in hex: 546869732069732061207265616C206669726D7761726520696D6167652E

### AES-KW + AES-GCM Example

This example uses the following parameters:

- Algorithm id for key wrap: A128KW
- KEK COSE_Key (Secret Key):
  - kty: Symmetric
  - k: 'aaaaaaaaaaaaaaaa'
  - kid: 'kid-1'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-aes-kw-aes-gcm.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aesgcm-example}}.

~~~
{::include examples/suit-encryption-info-aes-kw-aes-gcm.diag}
~~~
{: #aeskw-aesgcm-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-aes-kw-aes-gcm.hex}
~~~

### ECDH-ES+AES-KW + AES-GCM Example

This example uses the following parameters:

- Algorithm for content key distribution: ECDH-ES + A128KW
- KEK COSE_Key (Receiver's Private Key):
  - kty: EC2
  - crv: P-256
  - x: h'5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3'
  - y: h'9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B'
  - d: h'60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3'
  - kid: 'kid-2'
- KDF Context
  - Algorithm ID: -3 (A128KW)
  - SuppPubInfo
    - keyDataLength: 128
    - protected: { / alg / 1: -29 / ECDH-ES+A128KW / }
    - other: 'SUIT Payload Encryption'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-gcm.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aesgcm-example}}.

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-gcm.diag}
~~~
{: #esdh-aesgcm-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-es-ecdh-aes-gcm.hex}
~~~

## AES-CTR

### Introduction

AES-CTR is a non-AEAD cipher, provides confidentiality but no integrity protection.
Unlike AES-CBC, AES-CTR uses an IV per AES operation, as shown in {{aes-ctr-fig}}.
Hence, when an image is encrypted using AES-CTR-128 or AES-CTR-256, the IV MUST
start with zero (0) and MUST be incremented by one for each 16-byte plaintext block
within the entire slot.

Using the previous example with a slot size of 64 KiB, the sector size 4096 bytes and
the AES plaintext block size of 16 byte requires IVs from 0 to 255 in the first sector
and 16 * 256 IVs for the remaining sectors in the slot.

~~~ aasvg
         IV1            IV2
          |              |
          |              |
          |              |
      +-------+      +-------+
      |       |      |       |
      |       |      |       |
   k--|  E    |   k--|  E    |
      |       |      |       |
      +-------+      +-------+
          |              |
     P1---⊕        P2---⊕
          |              |
          |              |
          C1             C2
~~~
{: #aes-ctr-fig title="AES-CTR Operation"}

Note: The abbreviations shown in {{aes-ctr-fig}} are described
in {{content-enc}}.

Examples in this section use the following parameters:

- Algorithm for payload encryption: AES-CTR-128
  - k: h'261DE6165070FB8951EC5D7B92A065FE'
  - IV: h'DAE613B2E0DC55F4322BE38BDBA9DC68'
- Plaintext: "This is a real firmware image."
  - in hex: 546869732069732061207265616C206669726D7761726520696D6167652E

### AES-KW + AES-CTR Example

This example uses the following parameters:

- Algorithm id for key wrap: A128KW
- KEK COSE_Key (Secret Key):
  - kty: Symmetric
  - k: 'aaaaaaaaaaaaaaaa'
  - kid: 'kid-1'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-aes-kw-aes-ctr.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aesctr-example}}.

~~~
{::include examples/suit-encryption-info-aes-kw-aes-ctr.diag}
~~~
{: #aeskw-aesctr-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-aes-kw-aes-ctr.hex}
~~~

### ECDH-ES+AES-KW + AES-CTR Example

This example uses the following parameters:

- Algorithm for content key distribution: ECDH-ES + A128KW
- KEK COSE_Key (Receiver's Private Key):
  - kty: EC2
  - crv: P-256
  - x: h'5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3'
  - y: h'9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B'
  - d: h'60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3'
  - kid: 'kid-2'
- KDF Context
  - Algorithm ID: -3 (A128KW)
  - SuppPubInfo
    - keyDataLength: 128
    - protected: { / alg / 1: -29 / ECDH-ES+A128KW / }
    - other: 'SUIT Payload Encryption'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-ctr.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aesctr-example}}.

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-ctr.diag}
~~~
{: #esdh-aesctr-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-es-ecdh-aes-ctr.hex}
~~~

## AES-CBC

### Introduction

AES-CBC is a non-AEAD cipher, provides confidentiality but no integrity protection.
In AES-CBC, a single IV is used for encryption of firmware belonging to a single sector,
since individual AES blocks are chained together, as shown in {{aes-cbc-fig}}. The
numbering  of sectors in a slot start with zero (0) and increase by one with
every sector till the end of the slot is reached. The IV follows this numbering.

For example, let us assume the slot size of a specific flash controller on an IoT device
is 64 KiB, the sector size 4096 bytes (4 KiB) and AES-128-CBC uses an AES-block size of
128 bit (16 bytes). Hence, sector 0 needs 4096/16=256 AES-128-CBC operations using IV 0.
If the firmware image fills the entire slot, then that slot contains 16 sectors, i.e. IVs
ranging from 0 to 15.

~~~ aasvg
       P1              P2
        |              |
   IV---⊕    +--------⊕
        |     |        |
        |     |        |
    +-------+ |    +-------+
    |       | |    |       |
    |       | |    |       |
 k--|  E    | | k--|  E    |
    |       | |    |       |
    +-------+ |    +-------+
        |     |        |
        +-----+        |
        |              |
        |              |
        C1             C2
~~~
{: #aes-cbc-fig title="AES-CBC Operation"}

Note: The abbreviations shown in {{aes-cbc-fig}} are described
in {{content-enc}}.

Examples in this section use the following parameters:

- Algorithm for payload encryption: AES-CBC-128
  - k: h'627FCF0EA82C967D5ED8981EB325F303'
  - IV: h'93702C81590F845D9EC866CCAC767BD1'
- Plaintext: "This is a real firmware image."
  - in hex: 546869732069732061207265616C206669726D7761726520696D6167652E

### AES-KW + AES-CBC Example

This example uses the following parameters:

- Algorithm id for key wrap: A128KW
- KEK COSE_Key (Secret Key):
  - kty: Symmetric
  - k: 'aaaaaaaaaaaaaaaa'
  - kid: 'kid-1'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-aes-kw-aes-cbc.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aescbc-example}}.

~~~
{::include examples/suit-encryption-info-aes-kw-aes-cbc.diag}
~~~
{: #aeskw-aescbc-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-aes-kw-aes-cbc.hex}
~~~

### ECDH-ES+AES-KW + AES-CBC Example

This example uses the following parameters:

- Algorithm for content key distribution: ECDH-ES + A128KW
- KEK COSE_Key (Receiver's Private Key):
  - kty: EC2
  - crv: P-256
  - x: h'5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3'
  - y: h'9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B'
  - d: h'60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3'
  - kid: 'kid-2'
- KDF Context
  - Algorithm ID: -3 (A128KW)
  - SuppPubInfo
    - keyDataLength: 128
    - protected: { / alg / 1: -29 / ECDH-ES+A128KW / }
    - other: 'SUIT Payload Encryption'

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-cbc.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aescbc-example}}.

~~~
{::include examples/suit-encryption-info-es-ecdh-aes-cbc.diag}
~~~
{: #esdh-aescbc-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-es-ecdh-aes-cbc.hex}
~~~

# Integrity Check on Encrypted and Decrypted Payloads

In addition to suit-condition-image-match (see {{Section 8.4.9.2 of 
I-D.ietf-suit-manifest}}),
AEAD algorithms used for content encryption provides another way
to validate the integrity of components.
This section provides a guideline to construct secure but not redundant
SUIT Manifest for encrypted payloads.

## Validating Payload Integrity

This sub-section explains three ways to validate the integrity
of payloads.

### Image Match after Decryption

The suit-condition-image-match on the plaintext payload is used after decryption.
An example command sequence is shown in {{figure-image-match-after-decryption}}.

~~~
/ directive-set-component-index / 12, 1,
/ directive-override-parameters / 20, {
  / parameter-uri / 21: "http://example.com/encrypted.bin"
},
/ directive-fetch / 21, 15,

/ directive-set-component-index / 12, 0,
/ directive-override-parameters / 20, {
  / parameter-image-digest / 3: << {
    / algorithm-id: / -16 / SHA256 /,
    / digest-bytes: / h'3B1...92A' / digest of plaintext payload /
  } >>,
  / parameter-image-size / 14: 30 / size of plaintext payload /,
  / parameter-encryption-info / TBD19: h'369...50F',
  / parameter-source-component / 22: 1
},
/ directive-copy / 22, 15,
/ condition-image-match / 3, 15 / check decrypted payload integrity /,
~~~
{: #figure-image-match-after-decryption title="Check Image Match After Decryption"}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

### Image Match before Decryption

The suit-condition-image-match can also be applied on encrypted payloads
before decryption takes place. An example command sequence is shown in
{{figure-image-match-before-decryption}}.

This option mitigates battery exhaustion attacks discussed in {{sec-cons}}.

~~~
/ directive-set-component-index / 12, 1,
/ directive-override-parameters / 20, {
  / parameter-image-digest / 3: << {
    / algorithm-id: / -16 / SHA256 /,
    / digest-bytes: / h'8B4...D34' / digest of encrypted payload /
  } >>,
  / parameter-image-size / 14: 30 / size of encrypted payload /,
  / parameter-uri / 21: "http://example.com/encrypted.bin"
},
/ directive-fetch / 21, 15,
/ condition-image-match / 3, 15 / check decrypted payload integrity /,

/ directive-set-component-index / 12, 0,
/ directive-override-parameters / 20, {
  / parameter-encryption-info / TBD19: h'D86...1F0',
  / parameter-source-component / 22: 1
},
/ directive-copy / 22, 15,
~~~
{: #figure-image-match-before-decryption title="Check Image Match Before Decryption"}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

### Checking Authentication Tag while Decrypting

AEAD algorithms, such as AES-GCM and ChaCha20/Poly1305, verify the integrity of
the encrypted concent.

## Payload Integrity Validation

This sub-section provides a guideline to decide
how to validate the integrity of the payloads with the SUIT manifest.
{{payload-integrity-decision-tree}} illustrates a decision tree
to decide how to establish payload integrity.

~~~ aasvg
+------------------------------------------------+
|              Q1. Payload Delivery              |
+-+--------------------------------------------+-+
  |                                            |
  | in Content                          others |
  |                                            v
  |             +--------------------------------+
  |             |      Q2. Mitigate Battery      |
  |             |       Exhaustion Attacks       |
  |             +-+----------------------------+-+
  |               |                            |
  |               | No                     Yes |
  |               v                            |
  |    +-----------------+                     |
  |    | Q3. AEAD cipher |                     |
  |    +-+-------------+-+                     |
  |      |             |                       |
  |      | Yes      No |                       |
  v      v             v                       v
 .+------+.      .-----+-----.      .----------+.
|   NOT    |    |    AFTER    |    |   BEFORE    |
| Required |    | Decryption  |    | Decryption  |
 '--------'      '-----------'      '-----------'
~~~
{: #payload-integrity-decision-tree title="Decision Tree: Validating the Payload"}

There are three conditions:

- Q1. How does the recipient get the encrypted payload?
If the encrypted payload is an integrated payload,
its integrity is already validated with the suit-authentication-wrapper.
Hence, an additional integrity check is not required.

- Q2. Does the sender want to mitigate battery exhaustion attacks?
If yes, the encrypted payload has to be validated before decryption.

- Q3. Is the payload encrypted with an AEAD cipher?
If yes, the additional integrity check is not required because the recipient validates
the integrity of the payload while decrypting it. If no, validating its integrity
may take place either before or after decryption. Validating the integrity
before decryption is RECOMMENDED.

# Firmware Updates on IoT Devices with Flash Memory {#flash}

There are many flavors of embedded devices, the market is large and fragmented.
Hence, it is likely that some implementations and deployments implement their
firmware update procedure differently than described below. On a positive note,
the SUIT manifest allows different deployment scenarios to be supported easily
thanks to the "scripting" functionality offered by the commands.

This section is specific to firmware images on microcontrollers and does
not apply to generic software, configuration data, and machine learning models. 
The differences are the result of two aspects:

- Use of flash memory: Flash memory on microcontrollers is a type of non-volatile
memory that erases data in larger units called blocks, pages, or sectors and
re-writes data at the byte level (often 4-bytes) or larger units. Flash memory
is furthermore segmented into different memory regions, which store the
bootloader, different versions of firmware images (in so-called slots), and
configuration data. {{image-layout}} shows an example layout of a microcontroller
flash area.

- Microcontroller Design: Code on microcontrollers typically cannot be executed
from an arbitrary place in flash memory without extra software
development and design efforts. Hence, developers often compile firmware such
that the bootloader can execute the code from a specific location in flash
memory. Often, the location where the to-be-booted firmware image is found is
called "primary slot".

When the encrypted firmware image has been transferred to the device, it will
typically be stored in a dedicated area called the "secondary slot".

At the next boot, the bootloader will recognize a new firmware image and will
start decrypting the downloaded image sector-by-sector and will swap it with
the image found in the primary slot. This approach of swapping the newly
downloaded image with the previously valid image requires two slots to allow
the update to be reversed in case the newly obtained firmware image fails to
boot. This adds robustness to the firmware update procedure.

The swap will only take place after the signature on the plaintext is verified.
Note that the plaintext firmware image is available in the primary slot only after
the swap has been completed, unless "dummy decrypt" is used to compute the hash
over the plaintext prior to executing the decrypt operation during a swap.
Dummy decryption here refers to the decryption of the firmware image found in
the secondary slot sector-by-sector and computing a rolling hash over the resulting
plaintext firmware image (also sector-by-sector) without performing the swap operation.
While there are performance optimizations possible, such as conveying hashes for
each sector in the manifest rather than a hash of the entire firmware image,
such optimizations are not described in this specification.

Without hardware-based, on-the-fly decryption the image in the primary
slot is available in cleartext. It may need to be re-encrypted before copying it
to the secondary slot. This may be necessary when the secondary slot has different
access permissions or when it is located in off-chip flash memory. Off-chip flash
memory tends to be more vulnerable to physical attacks.

~~~ aasvg
+--------------------------------------------------+
| Bootloader                                       |
+--------------------------------------------------+
| Primary Slot                                     |
|                                        (sector 1)|
|..................................................|
|                                                  |
|                                        (sector 2)|
|..................................................|
|                                                  |
|                                        (sector 3)|
|..................................................|
|                                                  |
|                                        (sector 4)|
+--------------------------------------------------+
| Secondary Slot                                   |
|                                        (sector 1)|
|..................................................|
|                                                  |
|                                        (sector 2)|
|..................................................|
|                                                  |
|                                        (sector 3)|
|..................................................|
|                                                  |
|                                        (sector 4)|
+--------------------------------------------------+
| Swap Area                                        |
|                                                  |
+--------------------------------------------------+
| Configuration Data                               |
+--------------------------------------------------+
~~~
{: #image-layout title="Example Flash Area Layout"}

The ability to restart an interrupted firmware update is often a requirement
for unattended devices and the same is true for low-end, constrained IoT devices.
To fulfill this requirement it is necessary to chunk
a firmware image into sectors and to encrypt each sector individually
using a cipher that does not increase the size of the resulting ciphertext
(i.e., by not adding an authentication tag after each encrypted block).

When an update gets aborted while the bootloader is decrypting the newly obtained
image and swapping the sectors, the bootloader can restart where it left off. This
technique offers robustness and better performance.

For this purpose, ciphers without integrity protection are used to encrypt the
firmware image. Integrity protection of the firmware image MUST be provided
and the suit-parameter-image-digest, defined in {{Section 8.4.8.6 of
I-D.ietf-suit-manifest}}, MUST be used.

{{RFC9459}} registers AES Counter (AES-CTR) mode and AES Cipher Block Chaining
(AES-CBC) ciphers that do not offer integrity protection. These ciphers are useful
for use cases that require firmware encryption on IoT devices. For many other use
cases where software packages, configuration information or personalization data
need to be encrypted, the use of AEAD ciphers is RECOMMENDED.

The following sub-sections provide further information about the initialization vector
(IV) selection for use with AES-CBC and AES-CTR in the firmware encryption context. An
IV MUST NOT be re-used when the same key is used. For this application, the IVs are
not random but rather based on the slot/sector-combination in flash memory. The
text below assumes that the block-size of AES is (much) smaller than the sector size. The
typical sector-size of flash memory is in the order of KiB. Hence, multiple AES blocks
need to be decrypted until an entire sector is completed.

# Complete Examples 

The following manifests exemplify how to deliver encrypted payload and its
encryption info to devices.

HMAC-256 MAC are added in AES-KW examples using the following secret key:

~~~
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  (616161... in hex, and its length is 32)
~~~

ES-DH examples are signed using the following ECDSA secp256r1 key:

~~~
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgApZYjZCUGLM50VBC
CjYStX+09jGmnyJPrpDLTz/hiXOhRANCAASEloEarguqq9JhVxie7NomvqqL8Rtv
P+bitWWchdvArTsfKktsCYExwKNtrNHXi9OB3N+wnAUtszmR23M4tKiW
-----END PRIVATE KEY-----
~~~

The corresponding public key can be used to verify these examples:

~~~
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhJaBGq4LqqvSYVcYnuzaJr6qi/Eb
bz/m4rVlnIXbwK07HypLbAmBMcCjbazR14vTgdzfsJwFLbM5kdtzOLSolg==
-----END PUBLIC KEY-----
~~~

Each example uses SHA-256 as the digest function.

## AES Key Wrap Example with Write Directive {#example-AES-KW-write}

The following SUIT manifest requests a parser
to authenticate the manifest with COSE_Mac0 HMAC256, to write and 
decrypt the
encrypted payload into a component with the suit-directive-write
directive.

The SUIT manifest in diagnostic notation (with line breaks added for
readability) is shown here:

~~~
{::include examples/suit-manifest-aes-kw-content.diag.signed}
~~~

In hex format, the SUIT manifest is:

~~~
{::include examples/suit-manifest-aes-kw-content.hex.signed}
~~~


## AES Key Wrap Example with Fetch + Copy Directives {#example-AES-KW-copy}

The following SUIT manifest requests a parser to fetch the encrypted
payload and to store it. Then, the payload is decrypted and stored into
another component with the suit-directive-copy directive. This approach
works well on constrained devices with XIP flash memory.

The SUIT manifest in diagnostic notation (with line breaks added
for readability) is shown below.

~~~
{::include examples/suit-manifest-aes-kw.diag.signed}
~~~

The default storage area is defined by the component identifier (see
{{Section 8.4.5.1 of I-D.ietf-suit-manifest}}). In this example,
the component identifier for component #0 is ['plaintext-firmware']
and the file path "/plaintext-firmware" is the expected location.

While parsing the manifest, the behavior of SUIT manifest processor would be

- [L2-L17] authenticates the manifest part on [L18-L68]
- [L22-L25] gets two component identifiers; ['plaintext-firmware'] for component #0, and ['encrypted-firmware'] for component # 1 respectively
- [L29] sets current component index # 1 (the lasting directives target ['encrypted-firmware'])
- [L33-L34] sets source uri parameter "https://example.com/encrypted-firmware"
- [L36] fetches content from source uri into ['encrypted-firmware']
- [L39] sets current component index # 0 (the lasting directives target ['plaintext-firmware'])
- [L42-L62] sets SUIT encryption info parameter
- [L63-L64] sets source component index parameter # 1
- [L66] decrypts component # 1 (source component index) and stores the result into component # 0 (current component index)

The following attributes and features from the SUIT manifest specification are used:

| Attribute Name                             | Abbreviation  | Manifest Reference |
|--------------------------------------------|---------------|--------------------|
| component identifier                       | CI            | Section 8.4.5.1    |
| (destination) component index              | dst-CI        | Section 8.4.10.1   |
| (destination) component slot OPTIONAL param| dst-CS        | Section 8.4.8.8    |
| (source) uri OPTIONAL parameter            | src-URI       | Section 8.4.8.10   |
| source component index OPTIONAL parameter  | src-CI        | Section 8.4.8.11   |

The resulting state of SUIT manifest processor is shown in the following table:

| Abbreviation  | Plaintext              | Ciphertext                               |
|---------------|------------------------|------------------------------------------|
| CI            | ['plaintext-firmware'] | ['encrypted-firmware']                   |
| dst-CI        | 0                      | 1                                        |
| dst-CS        | N/A                    | N/A                                      |
| src-URI       | N/A                    | "https://example.com/encrypted-firmware" |
| src-CI        | 1                      | N/A                                      |

In hex format, the SUIT manifest shown above is:

~~~
{::include examples/suit-manifest-aes-kw.hex.signed}
~~~

The example above does not use storage slots. However, it is possible to specify this functionality for devices that support slots in flash memory. In the augmented example below we refer to the slots using [h'00'] and [h'01']. The component identifier [h'00'] would, in this example, specify the component slot #0.

~~~
{::include examples/suit-manifest-aes-kw-slot.diag.signed}
~~~

## ES-DH Example with Write + Copy Directives {#example-ES-DH-write}

The following SUIT manifest requests a parser to authenticate
the manifest with COSE_Sign1 ES256,
to write and decrypt the
encrypted payload into a component with the suit-directive-write
directive.

The SUIT manifest in diagnostic notation (with line breaks added for
readability) is shown here:

~~~
{::include examples/suit-manifest-es-ecdh-content.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~
{::include examples/suit-manifest-es-ecdh-content.hex.signed}
~~~

## ES-DH Example with Dependency {#example-ES-DH-dependency}

The following SUIT manifest requests a parser to resolve the dependency.

The dependent manifest is signed with another key:

~~~
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIQa67e56m8CYL5zVaJFiLl30j0qxb8ray2DeUMqH+qYoAoGCCqGSM49
AwEHoUQDQgAEDpCKqPBm2x8ITgw2UsY5Ur2Z8qW9si+eATZ6rQOrpot32hvYrE8M
tJC6IQZIv3mrFk1JrTVR1x0xSydJ7kLSmg==
-----END EC PRIVATE KEY-----
~~~

The dependency manifest is embedded as an integrated-dependency
and referred to by the  "#dependency-manifest" URI.

The SUIT manifest in diagnostic notation (with line breaks added for
readability) is shown here:

~~~
{::include examples/suit-manifest-es-ecdh-dependency.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~
{::include examples/suit-manifest-es-ecdh-dependency.hex.signed}
~~~

# Operational Considerations

The algorithms described in this document assume that the party
performing payload encryption

- shares a key-encryption key (KEK) with the recipient
  (for use with the AES Key Wrap scheme), or
- is in possession of the public key of the recipient
  (for use with ES-DH).

Both cases require some upfront communication interaction
to distribute these keys to the involved communication parties.
This interaction may be provided by a device management protocol,
as described in {{RFC9019}}, or may be executed earlier in
the lifecycle of the device, for example during manufacturing
or during commissioning. In addition to the keying material
key identifiers and algorithm information need to be provisioned.
This specification places no requirements on the structure of the
key identifier.

In some cases third party companies analyse binaries for known
security vulnerabilities. With encrypted payloads, this type of
analysis is prevented. Consequently, these third party companies
either need to be given access to the plaintext binary before
encryption or they need to become authorized recipients of the
encrypted payloads. In either case, it is necessary to explicitly
consider those third parties in the software supply chain when
such a binary analysis is desired.


# Security Considerations {#sec-cons}

This entire document is about security.

It is good security practise to use different keys for different purpose.
For example, the KEK used with an AES-KW-based content key distribution
method for encryption should be different from the long-term symmetric key
used for authentication in a communication security protocol.

To further reduce the attack surface it may be beneficial use different
long-term keys for the encryption of different types of payloads. For
example, KEK_1 may be used with an AES-KW content key distribution method
to encrypt a firmware image while KEK_2 would be used to encrypt
configuration data.

A large part of this document is focused on the content key distribution and
two methods are utilized, namely AES Key Wrap (AES-KW) and Ephemeral-Static
Diffie-Hellman (ES-DH). In this table we summarize the main properties with
respect to their deployment:

| Number of<br/>Long-Term<br/>Keys | Number of<br/>Content<br/>Encryption<br/>Keys (CEKs)                  | Use Case                                     | Recommended?         |
|----------------------------------|-----------------------------------------------------------------------|----------------------------------------------|----------------------|
| Same key<br/>for all<br/>devices | Single<br/>CEK per<br/>payload<br/>shared<br/>with all<br/>devies     | Legacy<br/>Usage                             | No, bad<br/>practice |
| One key<br/>per device           | Single<br/>CEK per<br/>payload<br/>shared<br/>with all<br/>devies     | Efficient<br/>Payload<br/>Distribution       | Yes                  |
| One Key<br/>per device           | One CEK<br/>per payload<br/>encryption<br/>transaction<br/>per device | Point-to-<br/>Point Payload<br/>Distribution | Yes                  |

The use of firmware encryption with IoT devices introduces an battery
exhaustion attack. This attack utilizes the fact that flash memory
operations are energy-expensive. To perform this attacker, the adversary
needs to be able to swap detached payloads and force the device to process
a wrong payload. Swapping the payloads is only possible when there is no
communication security protocol in place between the device and the
distribution system or when the distribution system itself is compromised.
The security features provided by the manifest will detect this attack and
the device will not boot the incorrectly provided payload. However, at this
time the energy-expensive flash operations have already been performed.
Consequently, these operations may reduce the lifetime of devices and
battery powered IoT devices are particularly vulnerable to such an attack.
See {{flash}} for further discussion about IoT devices using flash memory.

Including the digest of the encrypted payload in the manifest allows the
device to detect a battery exhaustion attack before energy consuming decryption
and flash memory copy or swap operations took place.

#  IANA Considerations

IANA is asked to add the following value to the SUIT Parameters
registry established by {{Section 11.5 of I-D.ietf-suit-manifest}}:

~~~
Label      Name                 Reference
-----------------------------------------
TBD19      Encryption Info      Section 4
~~~

RFC Editor's Note (TBD19): The value for the Encryption Info
parameter is set to 19, as the proposed value.

--- back

# Full CDDL {#full-cddl}

The following CDDL must be appended to the SUIT Manifest CDDL. The SUIT CDDL is defined in
Appendix A of {{I-D.ietf-suit-manifest}}

~~~ CDDL
{::include draft-ietf-suit-firmware-encryption.cddl}
~~~

# Acknowledgements
{: numbered="no"}

We would like to thank Henk Birkholz for his feedback on the CDDL description in this document.
Additionally, we would like to thank Michael Richardson, Øyvind Rønningstad, Dave Thaler, Laurence
Lundblade, Christian Amsüss, Ruud Derwig, Martin Thomson and Carsten Bormann for their review feedback. Finally,
we would like to thank Dick Brooks for making us aware of the challenges encryption imposes on
binary analysis.

Reviews from the IESG include Deb Cooley and Roman Danyliw.
