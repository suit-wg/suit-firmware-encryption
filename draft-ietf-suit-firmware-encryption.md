---
title: Encrypted Payloads in SUIT Manifests
abbrev: Encrypted Payloads in SUIT Manifests
docname: draft-ietf-suit-firmware-encryption-16
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
       ins: H. Tschofenig
       name: Hannes Tschofenig
       email: hannes.tschofenig@gmx.net

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
  I-D.ietf-cose-aes-ctr-and-cbc:
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

Our goal was to reduce the number of content key distribution methods
for use with payload encryption and thereby increase interoperability
between different SUIT manifest parser implementations.

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

The terms sender and recipient have the following meaning:

* Sender: Entity that sends an encrypted payload.
* Recipient: Entity that receives an encrypted payload.

Additionally, we introduce the term "distribution system" (or distributor)
to refer to an entity that knows the recipients of payloads. It is important
to note that the distribution system is far more than a file server. For
use of encryption, the distribution system either knows the public key
of the recipient (for ES-DH), or the KEK (for AES-KW).

The author, which is responsible for creating the payload, does not
know the recipients.

The author and the distribution system are logical roles. In some
deployments these roles are separated in different physical entities
and in others they are co-located.

# Architecture {#arch}

{{RFC9019}} describes the architecture for distributing payloads and
manifests from an author to devices. It does, however, not detail the
use of payload encryption. This document enhances the architecture to
support encryption.

{{arch-fig}} shows the distribution system, which represents a file
server and the device management infrastructure.

The sender (author) needs to know the recipient (device) to use encryption.
For AES-KW, the KEK needs to be known and, in case of ES-DH, the sender needs
to be in possession of the public key of the recipient. The public key and
parameters may be in the recipient's X.509 certificate {{RFC5280}}. For
authentication of the sender and for integrity protection the recipients
must be provisioned with a trust anchor when a manifest is protected using
a digital signature. When a MAC is used to protect the manifest then a
symmetric key must be shared by the recipient and the sender.

With encryption, the author cannot just create a manifest for the payload
and sign it, since the subsequent encryption step by the distribution
system would invalidate the signature over the manifest. (The content key
distribution information is embedded inside the COSE_Encrypt structure,
which is included in the SUIT manifest.) Hence, the author has to
collaborate with the distribution system. The varying degree of
collaboration is discussed below.

~~~
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
  and their keys from the distribution system. Then, it performs the necessary
  steps to encrypt the payload. As a last step it creates one or more manifests.
  The device(s) perform decryption and act as recipients.

* The author treats the distribution system as the initial recipient. Then,
  the distribution system decrypts and re-encrypts the payload for consumption
  by the device (or the devices). Delegating the task of re-encrypting
  the payload to the distribution system offers flexibility when the number
  of devices that need to receive encrypted payloads changes dynamically
  or when updates to KEKs or recipient public keys are necessary. As a downside,
  the author needs to trust the distribution system with performing the
  re-encryption of the payload.

If the author delegates encryption rights to the distributor two models are possible:

1. The distributor replaces the COSE_Encrypt in the manifest and then signs the
manifest again. However, the COSE_Encrypt structure is contained within a signed
container, which presents a problem: replacing the COSE_Encrypt with a new one
will cause the digest of the manifest to change, thereby changing the signature.
This means that the distributor must be able to sign the new manifest. If this
is the case, then the distributor  gains the ability to construct and sign
manifests, which allows the distributor the authority to sign code, effectively
presenting the distributor with full control over the recipient. Because
distributors typically perform their re-encryption online in order to handle
a large number of devices in a timely fashion, it is not possible to air-gap
the distributor's signing operations. This impacts the recommendations in
Section 4.3.17 of {{RFC9124}}.

2. The distributor uses a two-manifest system. More precisely, the distributor
constructs a new manifest that overrides the COSE_Encrypt using the dependency
system defined in {{I-D.ietf-suit-trust-domains}}. This incurs additional
overhead: one additional signature verification and one additional manifest,
as well as the additional machinery in the recipient needed for dependency
processing.

These two models also present different threat profiles for the distributor.
If the distributor only has encryption rights, then an attacker who breaches
the distributor can only mount a limited attack: they can encrypt a modified
binary, but the recipients will identify the attack as soon as they perform
the required image digest check and revert back to a correct image immediately.

It is RECOMMENDED that distributors are implemented using a two-manifest
system in order to distribute content encryption keys without requiring
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
wis supported. Mandating only a single content key distribution
method for a constrained device also reduces the code size.

~~~
SUIT_Parameters //= (suit-parameter-encryption-info
    => bstr .cbor SUIT_Encryption_Info)

suit-parameter-encryption-info = 19
~~~
{: #parameter-fig title="CDDL of the SUIT_Parameters Extension."}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.]

# Extended Directives

This specification extends these directives:

- Directive Write (suit-directive-write) to decrypt the content specified by
suit-parameter-content with suit-parameter-encryption-info.
- Directive Copy (suit-directive-copy) to decrypt the content of the component
specified by suit-parameter-source-component with suit-parameter-encryption-info.

Examples of the two directives are shown below.

{{encryption-info-consumed-with-write}} illustrates the Directive Write.
The encrypted payload specified with parameter-content, namely
h'EA1...CED' in the example, is decrypted using the SUIT_Encryption_Info
structure referred to by parameter-encryption-info, i.e., h'D86...1F0'.
The resulting plaintext payload is stored into component #0.

~~~
/ directive-override-parameters / 20, {
  / parameter-content / 18: h'EA1...CED',
  / parameter-encryption-info / 19: h'D86...1F0'
},
/ directive-write / 18, 15
~~~
{: #encryption-info-consumed-with-write title="Example showing the extended suit-directive-write."}

{{encryption-info-consumed-with-copy}} illustrates the Directive Copy.
In this example the encrypted payload is found at the URI indicated
by the parameter-uri, i.e. "http://example.com/encrypted.bin". The
encrypted payload will be downloaded and stored in component #1.
Then, the information in the SUIT_Encryption_Info structure of the
parameter-encryption-info, i.e. h'D86...1F0', will be used to
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
  / parameter-source-component / 22: 1,
  / parameter-encryption-info / 19: h'D86...1F0'
},
/ directive-copy / 22, 15
~~~
{: #encryption-info-consumed-with-copy title="Example showing the extended suit-directive-copy."}

The payload to be encrypted may be detached and, in that case, it is
not covered by the digital signature or the MAC protecting the manifest.
(To be more precise, the suit-authentication-wrapper found in the envelope
contains a digest of the manifest in the SUIT Digest Container.) 

The
lack of authentication and integrity protection of the payload is
particularly a concern when a cipher without integrity protection is
used.

To provide authentication and integrity protection of the payload
in the detached payload case a SUIT Digest Container with the hash
of the encrypted and/or plaintext payload MUST be included in the
manifest. See suit-parameter-image-digest parameter in Section
8.4.8.6 of {{I-D.ietf-suit-manifest}}.

Once a CEK is available, the steps described in {{content-enc}} are applicable.
These steps apply to both content key distribution methods.

# Content Key Distribution

The sub-sections below describe two content key distribution methods,
namely AES Key Wrap (AES-KW) and Ephemeral-Static Diffie-Hellman (ES-DH).
Many other methods are specified in the literature, and even supported
by COSE. New methods can be added via enhancements to this specification.
The two specified methods were selected to their maturity, different
security properties, and to ensure interoperability in deployments.

The two content key distribution methods require the CEKs to be
randomly generated. It must be ensured that the guidelines for random
number generation in {{RFC8937}} are followed.

When an encrypted payload is sent to multiple recipients, there
are different deployment options. To explain these options we use the
following notation:

~~~
   - KEK(R1, S) refers to a KEK shared between recipient R1 and
     the sender S. The KEK, as a concept, is used by AES Key Wrap
     but not by ES-DH.
   - CEK(R1, S) refers to a CEK shared between R1 and S.
   - CEK(*, S) or KEK(*, S) are used when a single CEK or a single
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
AES-KW are specified in Section 8.5.2 of {{RFC9052}} and in Section 6.2.1 of
{{RFC9053}}. The encrypted CEK is carried in the COSE\_recipient structure
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
     1. Fetch KEK(*, S)
     2. Generate CEK
     3. ENC(CEK, KEK)
     4. ENC(payload, CEK)
~~~

This deployment option is stronly discouraged. An attacker gaining access to
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
    2a.    Fetch KEK(Ri, S)
    2b.    ENC(CEK, KEK(Ri, S))
        }
    3.  ENC(payload, CEK)
~~~

- The third option is to use different CEKs encrypted with KEKs of
authorized recipients. This approach is appropriate when no benefits can
be gained from encrypting and transmitting payloads only once. Assume there
are n recipients with their unique KEKs - KEK(R1, S), ..., KEK(Rn, S).
The sender needs to execute the following steps:

~~~
    1.  for i=1 to n
        {
    1a.    Fetch KEK(Ri, S)
    1b.    Generate CEK(Ri, S)
    1c.    ENC(CEK(Ri, S), KEK(Ri, S))
    1d.    ENC(payload, CEK(Ri, S))
    2.  }
~~~


### CDDL

The CDDL for the COSE_Encrypt_Tagged structure is shown in {{cddl-aeskw}}.
empty_or_serialized_map and header_map are structures defined in {{RFC9052}}.

~~~
outer_header_map_protected = empty_or_serialized_map
outer_header_map_unprotected = header_map

SUIT_Encryption_Info_AESKW = [
  protected   : bstr .cbor outer_header_map_protected,
  unprotected : outer_header_map_unprotected,
  ciphertext  : bstr / nil,
  recipients  : [ + COSE_recipient_AESKW .within COSE_recipient ]
]

COSE_recipient_AESKW = [
  protected   : bstr .size 0 / bstr .cbor empty_map,
  unprotected : recipient_header_unpr_map_aeskw,
  ciphertext  : bstr        ; CEK encrypted with KEK
]

empty_map = {}

recipient_header_unpr_map_aeskw =
{
    1 => int,         ; algorithm identifier
  ? 4 => bstr,        ; identifier of the KEK pre-shared with the recipient
  * label => values   ; extension point
}
~~~
{: #cddl-aeskw title="CDDL for AES-KW-based Content Key Distribution"}

Note that the AES-KW algorithm, as defined in Section 2.2.3.1 of {{RFC3394}},
does not have public parameters that vary on a per-invocation basis. Hence,
the protected header in the COSE_recipient structure is a byte string
of zero length.

### Example

This example uses the following parameters:

- Algorithm for authentication: COSE_Mac0 with HMAC-256
- Algorithm for payload encryption: AES-GCM-128
- Algorithm id for key wrap: A128KW
- IV: h'93702C81590F845D9EC866CCAC767BD1'
- KEK: 'aaaaaaaaaaaaaaaa'
- KID: 'kid-1'
- Plaintext (txt): "This is a real firmware image."
  (in hex): 546869732069732061207265616C206669726D7761726520696D6167652E

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-aes-kw.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-example}}.

~~~
{::include examples/suit-encryption-info-aes-kw.diag}
~~~
{: #aeskw-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-aes-kw.hex}
~~~

## Content Key Distribution with Ephemeral-Static Diffie-Hellman {#ES-DH}

### Introduction

Ephemeral-Static Diffie-Hellman (ES-DH) is a scheme that provides public key
encryption given a recipient's public key. There are multiple variants
of this scheme; this document re-uses the variant specified in Section 8.5.5
of {{RFC9052}}.

The following two layer structure is used:

- Layer 0: Has a content encrypted with the CEK. The content may be detached.
- Layer 1: Uses the AES Key Wrap algorithm to encrypt the randomly generated
CEK with the KEK derived with ES-DH, whereby the resulting symmetric
key is fed into the HKDF-based key derivation function.

As a result, the two layers combine ES-DH with AES-KW and HKDF. An example is
given in {{esdh-example}}.

### Deployment Options

There are two deployment options with this approach. We assume that recipients
are always configured with a device-unique public / private key pair.

- A sender wants to transmit a payload to multiple recipients. All recipients
shall receive the same encrypted payload, i.e. the same CEK is used.
One COSE\_recipient structure per recipient is used and it contains the
CEK encrypted with the KEK. To generate the KEK each COSE\_recipient structure
contains a COSE_recipient_inner structure to carry the sender's ephemeral key
and an identifier for the recipients public key.

The steps taken by the sender are:

~~~
    1.  Generate CEK
    2.  for i=1 to n
        {
    2a.     Generate KEK(Ri, S) using ES-DH
    2b.     ENC(CEK, KEK(Ri, S))
        }
    3.  ENC(payload,CEK)
~~~

- The alternative is to encrypt a payload with a different CEK for each
recipient. This results in n-manifests. This approach is useful when payloads contain
information unique to a device. The encryption operation then effectively becomes
ENC(payload_i, CEK(Ri, S)). Assume that KEK(R1, S),..., KEK(Rn, S) have been generated
for the different recipients using ES-DH. The following steps need to be made
by the sender:

~~~
    1.  for i=1 to n
        {
    1a.     Generate KEK(Ri, S) using ES-DH
    1b.     Generate CEK(Ri, S)
    1c.     ENC(CEK(Ri, S), KEK(Ri, S))
    1d.     ENC(payload, CEK(Ri, S))
        }
~~~



### CDDL

The CDDL for the COSE_Encrypt_Tagged structure is shown in {{cddl-esdh}}.
Only the minimum number of parameters is shown. empty_or_serialized_map
and header_map are structures defined in {{RFC9052}}.

~~~
outer_header_map_protected = empty_or_serialized_map
outer_header_map_unprotected = header_map

SUIT_Encryption_Info_ESDH = [
  protected   : bstr .cbor outer_header_map_protected,
  unprotected : outer_header_map_unprotected,
  ciphertext  : bstr / nil,
  recipients  : [ + COSE_recipient_ESDH .within COSE_recipient ]
]

COSE_recipient_ESDH = [
  protected   : bstr .cbor recipient_header_map_esdh,
  unprotected : recipient_header_unpr_map_esdh,
  ciphertext  : bstr        ; CEK encrypted with KEK
]

recipient_header_map_esdh =
{
    1 => int,         ; algorithm identifier
  * label => values   ; extension point
}

recipient_header_unpr_map_esdh =
{
   -1 => COSE_Key,    ; ephemeral public key for the sender
  ? 4 => bstr,        ; identifier of the recipient public key
  * label => values   ; extension point
}
~~~
{: #cddl-esdh title="CDDL for ES-DH-based Content Key Distribution"}

See {{content-enc}} for a description on how to encrypt the payload.

### Context Information Structure

The context information structure is used to ensure that the derived keying material
is "bound" to the context of the transaction. This specification re-uses the structure
defined in Section 5.2 of {{RFC9053}} and tailors it accordingly.

The following information elements are bound to the context:

* the protocol employing the key-derivation method,
* information about the utilized AES Key Wrap algorithm, and the key length.
* the protected header field, which contains the content key encryption algorithm.

The sender and recipient identities are left empty.

The following fields in {{cddl-context-info}} require an explanation:

- The COSE_KDF_Context.AlgorithmID field MUST contain the algorithm identifier
for AES Key Wrap algorithm utilized. This specification uses the following
values: A128KW (value -4), A192KW (value -4), or A256KW (value -5)

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

~~~
PartyInfoSender = (
    identity : nil,
    nonce : nil,
    other : nil
)

PartyInfoRecipient = (
    identity : nil,
    nonce : nil,
    other : nil
)

COSE_KDF_Context = [
    AlgorithmID : int,
    PartyUInfo : [ PartyInfoSender ],
    PartyVInfo : [ PartyInfoRecipient ],
    SuppPubInfo : [
        keyDataLength : uint,
        protected : bstr .cbor recipient_header_map_esdh,
        other: bstr "SUIT Payload Encryption"
    ],
    SuppPrivInfo : bstr .size 0
]
~~~
{: #cddl-context-info title="CDDL for COSE_KDF_Context Structure"}

The HKDF-based key derivation function MAY contain a salt value,
as described in Section 5.1 of {{RFC9053}}. This optional value is used to
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

### Example

This example uses the following parameters:

- Algorithm for payload encryption: AES-GCM-128
- IV: h'3517CE3E78AC2BF3D1CDFDAF955E8600'
- Algorithm for content key distribution: ECDH-ES + A128KW
- SuppPubInfo.other = 'SUIT Payload Encryption'
- KID: 'kid-2'
- Plaintext: "This is a real firmware image."
- Plaintext (in hex encoding):
  546869732069732061207265616C206669726D7761726520696D6167652E

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
{::include examples/suit-encryption-info-es-ecdh.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-example}}. Note that the COSE_Encrypt structure also needs to
protected by a COSE_Sign1, which is not shown below.

~~~
{::include examples/suit-encryption-info-es-ecdh.diag}
~~~
{: #esdh-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~
{::include examples/encrypted-payload-es-ecdh.hex}
~~~

## Content Encryption {#content-enc}

This section summarizes the steps taken for content encryption, which
applies to both content key distribution methods.

For use with AEAD ciphers, the COSE specification requires a consistent byte
stream for the authenticated data structure to be created. This structure
is shown in {{cddl-enc-aeskw}} and is defined in Section 5.3 of {{RFC9052}}.

~~~
 Enc_structure = [
   context : "Encrypt",
   protected : empty_or_serialized_map,
   external_aad : bstr
 ]
~~~
{: #cddl-enc-aeskw title="CDDL for Enc_structure Data Structure"}

This Enc_structure needs to be populated as follows:

The protected field in the Enc_structure from {{cddl-enc-aeskw}} refers
to the content of the protected field from the COSE_Encrypt structure.

The value of the external_aad MUST be set to a zero-length byte string,
i.e., h'' in diagnostic notation and encoded as 0x40.

For use with ciphers that do not provide integrity protection, such as
AES-CTR and AES-CBC (see {{I-D.ietf-cose-aes-ctr-and-cbc}}), the
Enc_structure shown in {{cddl-enc-aeskw}} MUST NOT be used
because the Enc_structure represents the Additional Authenticated Data
(AAD) byte string consumable only by AEAD ciphers. Hence, the 
Additional Authenticated Data structure is not supplied to the 
API of the cipher. The protected header in the SUIT_Encryption_Info_AESKW
or SUIT_Encryption_Info_ESDH structure MUST be a zero-length byte string,
respectively.

# Firmware Updates on IoT Devices with Flash Memory {#flash}

Note: This section is specific to firmware images and does not apply to
generic software, configuration data, and machine learning models.

Flash memory on microcontrollers is a type of non-volatile memory that erases
data in units called blocks, pages, or sectors and re-writes data at the byte level
(often 4-bytes) or larger units.
Flash memory is furthermore segmented into different memory regions, which store
the bootloader, different versions of firmware images (in so-called slots),
and configuration data. {{image-layout}} shows an example layout of a
microcontroller flash area. The primary slot typically contains the firmware image
to be executed by the bootloader, which is a common deployment on devices that do
not offer the concept of position independent code. Position independent code
is not a feature frequently found in real-time operating systems used on
microcontrollers. There are many flavors of embedded devices, the market
is large and fragmented. Hence, it is likely that some implementations and deployments
implement their firmware update procedure different than described below.
On a positive note, the SUIT manifest allows different deployment scenarios
to be supported easily thanks to the "scripting" functionality offered by
the commands.

When the encrypted firmware image has been transferred to the device, it will
typically be stored in a staging area, in the secondary slot in our example.

At the next boot, the bootloader will recognize a new firmware image in the
secondary slot and will start decrypting the downloaded image sector-by-sector
and will swap it with the image found in the primary slot.

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

This approach of swapping the newly downloaded image with the previously valid
image requires two slots to allow the update to be reversed in case the newly obtained
firmware image fails to boot. This approach adds robustness to the firmware
update procedure.

Since the image in primary slot is available in cleartext, it may need to be
re-encrypted before copying it to the secondary slot. This may be necessary
when the secondary slot has different access permissions or when the staging
area is located in off-chip flash memory and is therefore more vulnerable to
physical attacks. Note that this description assumes that the processor does
not execute encrypted memory by using on-the-fly decryption in hardware.

~~~
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
for low-end IoT devices. To fulfill this requirement it is necessary to chunk
a firmware image into sectors and to encrypt each sector individually
using a cipher that does not increase the size of the resulting ciphertext
(i.e., by not adding an authentication tag after each encrypted block).

When an update gets aborted while the bootloader is decrypting the newly obtained
image and swapping the sectors, the bootloader can restart where it left off. This
technique offers robustness and better performance.

For this purpose, ciphers without integrity protection are used to encrypt the
firmware image. Integrity protection of the firmware image MUST be
provided and the suit-parameter-image-digest, defined in Section 8.4.8.6 of
{{I-D.ietf-suit-manifest}}, MUST be used.

{{I-D.ietf-cose-aes-ctr-and-cbc}} registers AES Counter (AES-CTR) mode and
AES Cipher Block Chaining (AES-CBC) ciphers that do not offer integrity protection.
These ciphers are useful for use cases that require firmware encryption on IoT
devices. For many other use cases where software packages, configuration information
or personalization data need to be encrypted, the use of Authenticated Encryption
with Associated Data (AEAD) ciphers is RECOMMENDED.

The following sub-sections provide further information about the initialization vector
(IV) selection for use with AES-CBC and AES-CTR in the firmware encryption context. An
IV MUST NOT be re-used when the same key is used. For this application, the IVs are
not random but rather based on the slot/sector-combination in flash memory. The
text below assumes that the block-size of AES is (much) smaller than the sector size. The
typical sector-size of flash memory is in the order of KiB. Hence, multiple AES blocks
need to be decrypted until an entire sector is completed.

## AES-CBC

In AES-CBC, a single IV is used for encryption of firmware belonging to a single sector,
since individual AES blocks are chained together, as shown in {{aes-cbc-fig}}. The
numbering  of sectors in a slot MUST start with zero (0) and MUST increase by one with
every sector till the end of the slot is reached. The IV follows this numbering.

For example, let us assume the slot size of a specific flash controller on an IoT device
is 64 KiB, the sector size 4096 bytes (4 KiB) and AES-128-CBC uses an AES-block size of
128 bit (16 bytes). Hence, sector 0 needs 4096/16=256 AES-128-CBC operations using IV 0.
If the firmware image fills the entire slot, then that slot contains 16 sectors, i.e. IVs
ranging from 0 to 15.

~~~
       P1              P2
        |              |
   IV--(+)    +-------(+)
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

Legend: 
  Pi = Plaintext blocks
  Ci = Ciphertext blocks
  E = Encryption function
  k = Symmetric key
  (+) = XOR operation
~~~
{: #aes-cbc-fig title="AES-CBC Operation"}

## AES-CTR

Unlike AES-CBC, AES-CTR uses an IV per AES operation, as shown in {{aes-ctr-fig}}.
Hence, when an image is encrypted using AES-CTR-128 or AES-CTR-256, the IV MUST
start with zero (0) and MUST be incremented by one for each 16-byte plaintext block
within the entire slot.

Using the previous example with a slot size of 64 KiB, the sector size 4096 bytes and
the AES plaintext block size of 16 byte requires IVs from 0 to 255 in the first sector
and 16 * 256 IVs for the remaining sectors in the slot.

~~~
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
     P1--(+)        P2--(+)
          |              |
          |              |
          C1             C2

Legend: 
  See previous diagram.
~~~
{: #aes-ctr-fig title="AES-CTR Operation"}

## Battery Exhaustion Attacks

The use of flash memory opens up for another attack. An attacker may swap
detached payloads and thereby force the device to process a wrong
payload. While this attack will be detected, a device may have performed
energy-expensive flash operations already. These operations may reduce
the lifetime of devices when they are battery powered Iot devices. See
{{flash}} for further discussion about IoT devices using flash memory.

Including the digest of the encrypted payload allows the device to
detect a battery exhaustion attack before energy consuming decryption
and flash operations took place. Including the digest of the plaintext
payload is adequate when battery exhaustion attacks are not a concern.



# Complete Examples 

The following manifests exemplify how to deliver encrypted payload and its
encryption info to devices.

HMAC-256 MAC are added in AES-KW examples using the following secret key:
~~~
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' (0x616161... in hex, and its length is 32)
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
to authenticate the manifest with COSE_Mac0 HMAC256,
and to write and to decrypt the
encrypted payload into a component with the suit-directive-write
directive.

The SUIT manifest in diagnostic notation (with line breaks added
for readability) is shown here:

~~~
{::include examples/suit-manifest-aes-kw-content.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~
{::include examples/suit-manifest-aes-kw-content.hex.signed}
~~~

## AES Key Wrap Example with Fetch + Copy Directives {#example-AES-KW-copy}

The following SUIT manifest requests a parser to fetch the encrypted
payload and to stores it. Then, the payload is decrypted and stored into
another component with the suit-directive-copy directive. This approach
works well on constrained devices with execute-in-place flash memory.

The SUIT manifest in diagnostic notation (with line breaks added for
readability) is shown here:

~~~
{::include examples/suit-manifest-aes-kw.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~
{::include examples/suit-manifest-aes-kw.hex.signed}
~~~

## ES-DH Example with Write + Copy Directives {#example-ES-DH-write}

The following SUIT manifest requests a parser to authenticate
the manifest with COSE_Sign1 ES256,
and to write and to decrypt the
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

The following SUIT manifest requests a parser
to resolve the delegation chain and dependency respectively.
The parser validates the COSE_Key in the suit-delegation section using the key above,
and then dynamically trusts it.
The dependency manifest is embedded as an integrated-dependency
and referred by uri "#dependency-manifest" .

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

Note that it is good security practise to use different long-term
keys for different purpose. For example, the KEK used with an
AES-KW-based content key distribution method for encryption should
be different from the long-term symmetric key used for authentication
and integrity protection when uses with COSE_Mac0.

The design of this specification allows to use different long-term
keys for encrypting payloads. For example, KEK_1 may be used with
an AES-KW content key distribution method to encrypt a firmware
image while KEK_2 would be used to encrypt configuration data. This
approach reduces the attack surface since permissions of authors to
these long-term keys may vary based on their privileges.


#  IANA Considerations

IANA is asked to add the following value to the SUIT Parameters
registry established by Section 11.5 of {{I-D.ietf-suit-manifest}}:

~~~
Label      Name                 Reference
-----------------------------------------
TBD19      Encryption Info      Section 4
~~~

[Editor's Note: TBD19: Proposed 19]

--- back

# A. Full CDDL {#full-cddl}

The following CDDL must be appended to the SUIT Manifest CDDL. The SUIT CDDL is defined in
Appendix A of {{I-D.ietf-suit-manifest}}

~~~ CDDL
{::include draft-ietf-suit-firmware-encryption.cddl}
~~~


# Acknowledgements
{: numbered="no"}

We would like to thank Henk Birkholz for his feedback on the CDDL description in this document.
Additionally, we would like to thank Michael Richardson, Øyvind Rønningstad, Dave Thaler, Laurence
Lundblade, Christian Amsüss, and Carsten Bormann for their review feedback. Finally, we would like
to thank Dick Brooks for making us aware of the challenges encryption imposes on binary analysis.
