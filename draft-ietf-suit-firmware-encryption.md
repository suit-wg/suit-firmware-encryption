---
title: Encrypted Payloads in SUIT Manifests
abbrev: Encrypted Payloads in SUIT Manifests
docname: draft-ietf-suit-firmware-encryption-23
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
  I-D.ietf-suit-mti:

informative:
  RFC9019:
  RFC9397:
  RFC9124:
  RFC5869:
  RFC8937:
  RFC5652:
  RFC5280:
  RFC5869:
  I-D.ietf-teep-usecase-for-cc-in-network:
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

Vulnerabilities in Internet of Things (IoT) devices have highlighted the need for a reliable and secure firmware update mechanism, especially for constrained devices. To protect firmware images, the SUIT manifest format was developed {{I-D.ietf-suit-manifest}}. A manifest is a bundle of metadata about the firmware for an IoT device, where to find the firmware, and the devices to which it applies. {{RFC9124}} outlines the necessary information a SUIT manifest has to provide. In addition to protecting against modification via digital signatures or message authentication codes, the format can also offer confidentiality.

Encryption prevents third parties, including attackers, from accessing the payload. Attackers often require detailed knowledge of a binary, such as a firmware image, to launch successful attacks. For instance, return-oriented programming (ROP) {{ROP}} requires access to the binary, and encryption makes writing exploits significantly more difficult. Beyond ensuring the confidentiality of the binary itself, protecting the confidentiality of the source code will also be necessary to prevent reverse engineering and reproduction of the firmware.

The initial motivation for this document was firmware encryption. However, the use of SUIT manifests has expanded to encompass other scenarios that require integrity and confidentiality protection, including:

- Software packages
- Personalization data
- Machine learning models

These additional use cases stem from the work on Trusted Execution Environment Provisioning (TEEP), as detailed in {{RFC9397}} and {{I-D.ietf-teep-usecase-for-cc-in-network}}. The distinction between software and firmware is clarified in {{RFC9019}}.

For consistency and simplicity, we use the term "payload" generically to refer to all objects subject to encryption.

The payload is encrypted using a symmetric content encryption key, which can be established through various mechanisms. This document defines two content key distribution methods for use with the SUIT manifest:

- Ephemeral-Static (ES) Diffie-Hellman (DH), and
- AES Key Wrap (AES-KW).

The first method relies on asymmetric cryptography, while the second uses symmetric cryptography.

Our design aims to reduce the number of content key distribution methods for payload encryption, thereby increasing interoperability between different SUIT manifest parser implementations. The mandatory-to-implement
algorithms are described in a separate document {{I-D.ietf-suit-mti}}.

The goal of this specification is to protect payloads both during end-to-end transport (from the distribution system to the device) and at rest when stored on the device. Constrained devices often employ eXecute In Place (XIP), a method of executing code directly from flash memory rather than loading it into RAM. Many of these devices lack hardware-based, on-the-fly decryption for code stored in flash memory, which may require decrypting and storing firmware images in on-chip flash before execution. However, we expect hardware-based, on-the-fly decryption to become more common in the future, enhancing confidentiality at rest.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document assumes familiarity with the SUIT manifest {{I-D.ietf-suit-manifest}},
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
know the recipients. The author may, for example, be a developer building
a firmware image.

The author and the distribution system are logical roles. In some
deployments these roles are separated in different physical entities
and in others they are co-located.

# Architecture {#arch}

{{RFC9019}} outlines the architecture for distributing payloads and manifests from an author to devices. However, it does not cover payload encryption in detail. This document extends that architecture to support encryption, as illustrated in {{arch-fig}}.

To encrypt a payload, it is essential to know the recipient. For AES-KW, the Key Encryption Key (KEK) must be known, and for ES-DH, the sender needs access to the recipient's public key. This public key and its associated parameters may be found in the recipient's X.509 certificate {{RFC5280}}. For authentication and integrity protection, recipients must be provisioned with a trust anchor when the manifest is protected by a digital signature. If a MAC is used for manifest protection, a symmetric key must be shared between the recipient and the sender.

With encryption, the author cannot simply create and sign a manifest for the payload, as the recipients are often unknown. Therefore, the author must collaborate with the distribution system. The degree of this collaboration is discussed below.

The primary purpose of encryption is to protect against adversaries along the path between the distribution system and the device. There is also a risk that adversaries may extract the decrypted firmware image from the device itself. Consequently, the device must be safeguarded against physical attacks. Such countermeasures are outside the scope of this specification.

Note: It is assumed that a mutually authenticated communication channel with integrity and confidentiality protection exists between the author and the distribution system. For example, the author could upload the manifest and firmware image to the distribution system via a mutually authenticated HTTPS REST API.

~~~ aasvg
 +----------+
 |  Device  |                              +----------+
 |    1     |<--+                          |  Author  |
 |          |   |                          +----+-----+
 +----------+   |                               |
                |                               | Payload +
                |                               | Manifest
                |                               v
 +----------+   |                        +--------------+
 |  Device  |   |  Payload + Manifest    | Distribution |
 |    2     |<--+------------------------+    System    |
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

When the author delegates encryption rights to the distributor, two models are possible:

1. Replacing the COSE_Encrypt and Re-signing the Manifest:
The distributor replaces the COSE_Encrypt structure in the manifest and then signs the manifest again. However, since the COSE_Encrypt structure is within a signed container, this presents a challenge: replacing COSE_Encrypt alters the digest of the manifest, thereby invalidating the signature. As a result, the distributor must be able to sign the new manifest. If this is the case, the distributor gains the authority to construct and sign manifests, effectively allowing them to sign code and giving them full control over the recipient. Distributors typically perform re-encryption online to manage large numbers of devices efficiently, which prevents air-gapping the signing operations. This approach necessitates the secure storage of signing keys, as outlined in {{Section 4.3.17 and Section 4.3.18 of RFC9124}}. Despite these issues, this model represents the current standard practice for IoT firmware updates.

2. Two-Layer Manifest System:
The distributor creates a new manifest that overrides the COSE_Encrypt using the dependency system defined in {{I-D.ietf-suit-trust-domains}}. This method introduces additional overhead, including one more signature verification, one extra manifest, and the need for extra mechanisms on the recipient side to handle dependency processing. While this adds complexity, it also enhances security.

These two models offer different threat profiles for the distributor. If the distributor is limited to encryption rights, an attacker who breaches the distributor can only launch a limited attack by encrypting a modified binary. However, recipients will detect the attack during the image digest check and immediately revert to the correct image.

It is RECOMMENDED that distributors adopt the two-layer manifest approach to distribute content encryption keys without re-signing the manifest, despite the added complexity and the increased number of signature verifications required on the recipient side.

# Encryption Extensions {#parameters}

Extending the SUIT manifest to support payload encryption requires minimal
changes and is achieved by adding the suit-parameter-encryption-info field
to the SUIT_Parameters structure, as illustrated in {{parameter-fig}}. When
the suit-parameter-encryption-info is included, the manifest processor will
attempt to decrypt data during copy or write operations.

The SUIT_Encryption_Info structure contains the content key distribution
information. The details of the SUIT_Encryption_Info structure are provided
in {{AES-KW}} (for AES-KW) and {{ES-DH}} (for ES-DH).

~~~ cddl
SUIT_Parameters //= (suit-parameter-encryption-info
    => bstr .cbor SUIT_Encryption_Info)

suit-parameter-encryption-info = TBD19
~~~
{: #parameter-fig title="CDDL of the SUIT_Parameters Extension."}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

Once a CEK is available, the steps outlined in {{content-enc}} apply to both
content key distribution methods described in this section.

When used with the "Directive Write" and "Directive Copy" directives, the
SUIT_Encryption_Info structure MUST be included in either the
suit-directive-override-parameters or the suit-directive-set-parameters.
An implementation conforming to this specification MUST support both of these parameters.

## Directive Write

An author uses the Directive Write (suit-directive-write) to decrypt the content specified
by suit-parameter-content using suit-parameter-encryption-info. This directive is used to
write a specific data directly to a component.

{{encryption-info-consumed-with-write}} illustrates an example of the Directive Write,
which is described in the CDDL in {{parameter-fig}}. The
encrypted payload specified by parameter-content, represented as h'EA1...CED'
in the example, is decrypted using the SUIT_Encryption_Info structure referenced
by parameter-encryption-info, i.e., h'D86...1F0' in L3. The resulting plaintext payload
is then stored in component #0, which is the default if no specific component is explicitly designated.

~~~
/  1/  / directive-override-parameters / 20, {
/  2/    / parameter-content / 18: h'EA1...CED',
/  3/    / parameter-encryption-info / TBD19: h'D86...1F0'
/  4/  },
/  5/  / directive-write / 18, 15
~~~
{: #encryption-info-consumed-with-write title="Example showing the extended suit-directive-write."}

RFC Editor's Note (TBD19): The value for the parameter-encryption-info
parameter is set to 19, as the proposed value.

## Directive Copy

An author uses the Directive Copy (suit-directive-copy) to decrypt the content of the
component specified by suit-parameter-source-component using suit-parameter-encryption-info.
This directive is used to copy data from one component to another.

{{encryption-info-consumed-with-copy}} illustrates the Directive Copy.
In this example the encrypted payload is found at the URI indicated
by the parameter-uri, i.e., "coaps://example.com/encrypted.bin" in L3. The
encrypted payload will be downloaded and stored in component #1,
as indicated by directive-set-component-index in L1.

Then, the information in the SUIT_Encryption_Info structure referred
to by parameter-encryption-info, i.e., h'D86...1F0' in L9, will be used to
decrypt the content in component #1 and the resulting plaintext
payload will be stored into component #0 (as set in L7).
The command in L12 invokes the operation. 

~~~
/  1/  / directive-set-component-index / 12, 1,
/  2/  / directive-override-parameters / 20, {
/  3/    / parameter-uri / 21: "coaps://example.com/encrypted.bin",
/  4/   },
/  5/  / directive-fetch / 21, 15,
/  6/
/  7/  / directive-set-component-index / 12, 0,
/  8/  / directive-override-parameters / 20, {
/  9/    / parameter-encryption-info / TBD19: h'D86...1F0',
/ 10/    / parameter-source-component / 22: 1
/ 11/  },
/ 12/  / directive-copy / 22, 15
~~~
{: #encryption-info-consumed-with-copy title="Example showing the extended suit-directive-copy."}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

## Authenticating the Payload

The payload to be encrypted MAY be detached and, in that case, it is
not covered by the digital signature or the MAC protecting the manifest.
(To be more precise, the suit-authentication-wrapper found in the envelope
contains a digest of the manifest in the SUIT Digest Container.) 

The lack of authentication and integrity protection of the payload is
particularly a concern when a cipher without integrity protection is
used.

To provide authentication and integrity protection of the payload
in the detached case a SUIT Digest Container with the hash
of the encrypted and/or plaintext payload MUST be included in the
manifest. See suit-parameter-image-digest parameter in {{Section
8.4.8.6 of I-D.ietf-suit-manifest}}.

Once a CEK is available, the steps described in {{content-enc}} are applicable.
These steps apply to both content key distribution methods.

More detailed examples for the two directives can be found in {{example-AES-KW-write}}.

# Content Key Distribution {#content-key-distribution}

The following sub-sections describe two content key distribution methods:
AES Key Wrap (AES-KW) and Ephemeral-Static Diffie-Hellman (ES-DH). While
many other methods are specified in the literature and supported by COSE,
AES-KW and ES-DH were chosen for their widespread use in the market today.
They were selected for their maturity, differing security properties, and
strong interoperability.

Interoperability requirements for content key distribution methods differ:
since a device typically supports only one of the two specified methods,
the distribution system must be aware of the supported method.
Restricting a constrained device to a single content key distribution
method also helps minimize code size.

Both content key distribution methods require the CEKs to be randomly
generated. The guidelines for random number generation in {{RFC8937}}
MUST be followed.

When sending an encrypted payload to multiple recipients, various
deployment options are available. The following notation is used to
explain these options:

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

The AES Key Wrap (AES-KW) algorithm, as described in {{RFC3394}},
is used to encrypt a randomly generated content-encryption key (CEK)
with a pre-shared key-encryption key (KEK). The COSE conventions for using
AES-KW are specified in {{Section 8.5.2 of RFC9052}} and in {{Section 6.2.1 of
RFC9053}}. The encrypted CEK is carried within the COSE\_recipient structure
, which includes the necessary information for AES-KW. The COSE\_recipient structure,
a substructure of COSE\_Encrypt, contains the CEK
encrypted by the KEK.

To ensure high security when using AES Key Wrap, it is important that the
KEK is of high entropy and that implementations protect the KEK
from disclosure. A compromised KEK could expose all data encrypted with it,
including binaries and configuration data.

The COSE\_Encrypt structure conveys the information needed to encrypt the payload,
including details such as the algorithm and IV. Even though the payload may
be conveyed as detached content, the encryption information is still embedded
in the COSE_Encrypt.ciphertext structure.

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

### The CDDL of SUIT_Encryption_Info for AES-KW binary

The CDDL for the AES-KW binary is shown in {{cddl-aeskw}}.
empty_or_serialized_map and header_map are structures defined in {{RFC9052}}.

~~~ cddl
{::include-fold cddls/aeskw.cddl}
~~~
{: #cddl-aeskw title="CDDL for AES-KW-based Content Key Distribution"}

Note that the AES-KW algorithm, as defined in {{Section 2.2.3.1 of RFC3394}},
does not have public parameters that vary on a per-invocation basis. Hence,
the protected header in the COSE_recipient structure is a byte string
of zero length.

## Content Key Distribution with Ephemeral-Static Diffie-Hellman {#ES-DH}

### Introduction

Ephemeral-Static Diffie-Hellman (ES-DH) is a public key encryption scheme
that enables encryption using the recipient's public key. There are several
variations of this scheme; this document adopts the version specified in
{{Section 8.5.5 of RFC9052}}.

The structure is composed of two layers:

- Layer 0: Contains content encrypted with a Content Encryption Key (CEK).
The content may be provided separately.

- Layer 1: Uses the AES Key Wrap (AES-KW) algorithm to encrypt the randomly
generated CEK with a Key Encryption Key (KEK) derived via ES-DH. The
resulting symmetric key is processed through an HKDF-based key derivation
function {{RFC5869}}.

This two-layer structure combines ES-DH with AES-KW and HKDF, referred to
as ECDH-ES + AES-KW. An example can be found in {{esdh-aesgcm-example}}.

Another variant of the ES-DH algorithm, called ECDH-ES + HKDF, does not
utilize AES Key Wrap. However, this version is not covered in this document.

### Deployment Options

This approach supports only two deployment options, as it assumes that each
recipient is always equipped with a device-specific public/private key pair.

- When a sender transmits a payload to multiple recipients, all recipients
receive the same encrypted payload, meaning the same CEK is used to encrypt
the content. For each recipient, a separate COSE\_recipient structure is used,
which contains the CEK encrypted with the recipient-specific KEK. To derive
the KEK, each COSE\_recipient structure includes a COSE\_recipient\_inner
structure that carries the sender's ephemeral key and an identifier for the
recipient's public key.

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

- The alternative is to encrypt each device specific payload with a unique content encryption
key (CEK), resulting in a manifest per device specific payload. his approach is useful when payloads contain
device-specific information or when the optimization in previous approach are not applicable
or not valuable enough. In this case, the encryption operation becomes
ENC(payload_i, CEK[Ri, S]) where each recipient Ri receives a unique CEK. Assume
that KEK[R1, S],..., KEK[Rn, S] have been generated for the recipients using ES-DH.
The sender must then follow these steps:

~~~
    1.  for i=1 to n
        {
    1a.     Generate KEK[Ri, S] using ES-DH
    1b.     Generate CEK[Ri, S]
    1c.     ENC(CEK[Ri, S], KEK[Ri, S])
    1d.     ENC(payload, CEK[Ri, S])
        }
~~~

### The CDDL of SUIT_Encryption_Info for ES-DH binary

The CDDL for the ECDH-ES+AES-KW binary is provided in {{cddl-esdh}}.
Only the essential parameters are included. The structures empty_or_serialized_map
and header_map are defined in {{RFC9052}}.

~~~ cddl
{::include-fold cddls/esdh_aeskw.cddl}
~~~
{: #cddl-esdh title="CDDL for ES-DH-based Content Key Distribution"}

See {{content-enc}} for a description on how to encrypt the payload.

### Context Information Structure

The context information structure ensures that the derived keying material
is "bound" to the specific context of the transaction. This specification
reuses the structure defined in {{Section 5.2 of RFC9053}}, with modifications
to fit the current use case.

The following elements are bound to the context:

* the protocol employing the key-derivation method,
* information about the utilized AES Key Wrap algorithm, and the key length.
* the protected header field, which contains the content key encryption algorithm.

The sender and recipient identities are left empty.

The following fields in {{cddl-context-info}} require an explanation:

- The COSE_KDF_Context.AlgorithmID field MUST contain the identifier for the
AES Key Wrap algorithm being used. This specification uses the following
values: A128KW (value -3), A192KW (value -4), or A256KW (value -5)

- The COSE_KDF_Context.SuppPubInfo.keyDataLength field MUST specify the key
length, in bits, corresponding to the algorithm in the AlgorithmID field.
For A128KW the value is 128, for A192KW the value is 192, and for A256KW
the value 256.

- The COSE_KDF_Context.SuppPubInfo.other field captures the protocol that
uses the ES-DH content key distribution algorithm. It MUST be set to
the constant string "SUIT Payload Encryption".

- The COSE_KDF_Context.SuppPubInfo.protected field MUST contain the serialized
content of the recipient_header_map_esdh field, which contains (among other
elements) the identifier of the content key distribution method.

~~~ cddl
{::include-fold cddls/kdf-context.cddl}
~~~
{: #cddl-context-info title="CDDL for COSE_KDF_Context Structure"}

The HKDF-based key derivation function MAY contain a salt value,
as described in {{Section 5.1 of RFC9053}}. This optional value
influences the key generation process, though this specification
does not require the use of a salt.  If the salt is public and
included in the message, the "salt" algorithm header parameter
MUST be used. The salt adds extra randomness to the KDF context.
When the salt is transmitted via the "salt" algorithm header
parameter, the receiver MUST be capable of processing it and MUST
pass it into the key derivation function. For more details on salt
usage, refer to {{RFC5869}} and NIST SP800-56 {{SP800-56}}.

Profiles of this specification MAY define an extended version of
the context information structure or MAY employ a different context
information structure.

# Content Encryption {#content-enc}

This section summarizes the steps involved in content encryption,
applicable to both content key distribution methods.

When using AEAD ciphers, such as AES-GCM or ChaCha20/Poly1305, the
COSE specification requires a consistent byte stream to create the
authenticated data structure. This structure is illustrated in
{{cddl-enc-aeskw}} and defined in {{Section 5.3 of RFC9052}}.

~~~ cddl
 Enc_structure = [
   context : "Encrypt",
   protected : empty_or_serialized_map,
   external_aad : bstr
 ]
~~~
{: #cddl-enc-aeskw title="CDDL for Enc_structure Data Structure"}

This Enc_structure must be populated as follows:

- The protected field in the Enc_structure from {{cddl-enc-aeskw}} refers
to the content of the protected field in the COSE_Encrypt structure.

- The value of external_aad MUST be set to a zero-length byte string,
 represented as h'' in diagnostic notation and encoded as 0x40.

Some ciphers, such as AES-CTR and AES-CBC, provide confidentiality
without integrity protection (see {{RFC9459}}). For these ciphers,
the Enc_structure shown in {{cddl-enc-aeskw}} cannot be used, as
the Additional Authenticated Data (AAD) byte string is only
applicable to AEAD ciphers. Therefore, the AAD structure is not
passed to the API for these ciphers, and the protected header in
the SUIT_Encryption_Info structure MUST be a zero-length byte string.

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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-aes-kw-aes-gcm.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aesgcm-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-aes-kw-aes-gcm.diag}
~~~
{: #aeskw-aesgcm-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-aes-kw-aes-gcm.hex}
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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-es-ecdh-aes-gcm.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aesgcm-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-es-ecdh-aes-gcm.diag}
~~~
{: #esdh-aesgcm-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-es-ecdh-aes-gcm.hex}
~~~

## AES-CTR

### Introduction

AES-CTR is a non-AEAD cipher that provides confidentiality but lacks integrity protection.
Unlike AES-CBC, AES-CTR uses an IV per block, as shown in {{aes-ctr-fig}}.
Hence, when an image is encrypted using AES-CTR-128 or AES-CTR-256, the IV MUST
start with zero (0) and MUST be incremented by one for each 16-byte plaintext block
within the entire slot.

In our example, we assume the slot size of a specific flash controller on an IoT device
is 64 KiB, the sector size 4096 bytes (4 KiB) and an AES plaintext block size of 16 bytes,
the IVs range from 0 to 255 in the first sector, and 16 * 256 IVs are required for the
remaining sectors in the slot.

~~~ aasvg
         IV1            IV2
          |              |
          |              |
          |              |
      +---+---+      +---+---+
      |       |      |       |
      |       |      |       |
   k--+   E   |   k--+   E   |
      |       |      |       |
      +---+---+      +---+---+
          |              |
     P1---⊕         P2---⊕
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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-aes-kw-aes-ctr.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aesctr-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-aes-kw-aes-ctr.diag}
~~~
{: #aeskw-aesctr-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-aes-kw-aes-ctr.hex}
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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-es-ecdh-aes-ctr.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aesctr-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-es-ecdh-aes-ctr.diag}
~~~
{: #esdh-aesctr-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-es-ecdh-aes-ctr.hex}
~~~

## AES-CBC

### Introduction

AES-CBC is a non-AEAD cipher that provides confidentiality but does not offer
integrity protection.
In AES-CBC, a single IV is used to  encrypt the firmware belonging to a single sector,
as  individual AES blocks are chained together, as illustrated  in {{aes-cbc-fig}}. The
numbering  of sectors in a slot start with zero (0) and increase by one with
every sector till the end of the slot is reached. The IV follows this numbering.

For example, let us assume the slot size of a specific flash controller on an IoT device
is 64 KiB, the sector size 4096 bytes (4 KiB) and AES-128-CBC uses an AES-block size of
128 bit (16 bytes). Hence, sector 0 needs 4096/16=256 AES-128-CBC operations using IV 0.
If the firmware image occupies the entire slot, it will contain 16 sectors, corresponding
to IVs ranging from 0 to 15.

~~~ aasvg
        P1             P2
        |              |
   IV---⊕     +--------⊕
        |     |        |
        |     |        |
    +---+---+ |    +---+---+
    |       | |    |       |
    |       | |    |       |
 k--+   E   | | k--+   E   |
    |       | |    |       |
    +---+---+ |    +---+---+
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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-aes-kw-aes-cbc.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-aescbc-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-aes-kw-aes-cbc.diag}
~~~
{: #aeskw-aescbc-example title="COSE_Encrypt Example for AES Key Wrap"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-aes-kw-aes-cbc.hex}
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

~~~ test-vectors
{::include-fold examples/suit-encryption-info-es-ecdh-aes-cbc.hex}
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{esdh-aescbc-example}}.

~~~ cbor-diag
{::include-fold examples/suit-encryption-info-es-ecdh-aes-cbc.diag}
~~~
{: #esdh-aescbc-example title="COSE_Encrypt Example for ES-DH"}

The encrypted payload (with a line feed added) was:

~~~ test-vectors
{::include-fold examples/encrypted-payload-es-ecdh-aes-cbc.hex}
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
  / parameter-uri / 21: "coaps://example.com/encrypted.bin"
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
/ condition-image-match / 3, 15 / check decrypted payload integrity /
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
  / parameter-uri / 21: "coaps://example.com/encrypted.bin"
},

/ directive-fetch / 21, 15,
/ condition-image-match / 3, 15 / check decrypted payload integrity /,

/ directive-set-component-index / 12, 0,
/ directive-override-parameters / 20, {
  / parameter-encryption-info / TBD19: h'D86...1F0',
  / parameter-source-component / 22: 1
},
/ directive-copy / 22, 15
~~~
{: #figure-image-match-before-decryption title="Check Image Match Before Decryption"}

RFC Editor's Note (TBD19): The value for the suit-parameter-encryption-info
parameter is set to 19, as the proposed value.

### Checking Authentication Tag while Decrypting

AEAD algorithms, such as AES-GCM and ChaCha20/Poly1305, verify the integrity of
the encrypted concent.

## Payload Integrity Validation

This subsection offers guidelines for validating the integrity of payloads within
the SUIT manifest. The decision tree in {{payload-integrity-decision-tree}}
illustrates the process for establishing payload integrity.

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

There are three questions to ask:

- Q1. How does the recipient receive the encrypted payload?
If the encrypted payload is part of an integrated payload, its integrity is already validated by the suit-authentication-wrapper. Hence, no additional integrity check is necessary.

- Q2. Does the sender wish to mitigate battery exhaustion attacks?
If so, the encrypted payload must be validated before decryption.

- Q3. Is the payload encrypted with an AEAD cipher?
If yes, no additional integrity check is required, as the recipient verifies
the payload's integrity during decryption. If no, integrity validation can
occur either before or after decryption; however, validating integrity before
decryption is RECOMMENDED.

# Firmware Updates on IoT Devices with Flash Memory {#flash}

Embedded devices come in many forms, and the market is both large and fragmented.
As a result, some implementations and deployments may adopt firmware update
procedures that differ from the descriptions provided here. On a positive note,
the SUIT manifest accommodates various deployment scenarios, thanks to the
"scripting" functionality offered by its commands.

This section specifically addresses firmware images on microcontrollers and does
not pertain to generic software, configuration data, or machine learning models.
The differences arise from two main aspects:

- Use of Flash Memory: Flash memory in microcontrollers is a type of non-volatile
memory that typically erases data in larger units called blocks, pages, or sectors,
and rewrites data at the byte level (often 4 bytes) or larger units. Furthermore,
flash memory is segmented into different regions, storing the bootloader, various
versions of firmware images (in designated slots), and configuration data. An
example layout of a microcontroller flash area is illustrated in {{image-layout}}.

- Microcontroller Design: Code on microcontrollers typically cannot be executed
from arbitrary locations in flash memory without additional software development
and design efforts. Consequently, developers often compile firmware so that the
bootloader can execute code from a specific location in flash memory, commonly
referred to as the "primary slot."

Once the encrypted firmware image is transferred to the device, it is usually
stored in a dedicated area known as the "secondary slot."

During the next boot, the bootloader detects the new firmware image and begins
decrypting it sector by sector, swapping it with the image located in the primary
slot. This method of swapping the newly downloaded image with the previously
valid one requires two slots, allowing for a rollback if the new firmware fails
to boot, thereby enhancing the robustness of the firmware update process.

The swap occurs only after verifying the signature on the plaintext. It is
important to note that the plaintext firmware image is available in the primary
slot only after the swap is completed, unless "dummy decrypt" is used to compute
the hash over the plaintext prior to executing the decryption during the swap.
In this context, dummy decryption refers to decrypting the firmware image in the
secondary slot sector by sector while computing a rolling hash over the resulting
plaintext (also sector by sector) without performing the swap operation. Although
performance optimizations, such as conveying hashes for each sector in the manifest
rather than a hash of the entire firmware image, are possible, these optimizations
are not detailed in this specification.

Without hardware-based, on-the-fly decryption, the image in the primary slot is
available in cleartext and may need to be re-encrypted before copying it to the
secondary slot. This step might be necessary if the secondary slot has different
access permissions or is located in off-chip flash memory, which tends to be more
vulnerable to physical attacks.

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

The ability to resume an interrupted firmware update is often essential
for unattended devices, including low-end, constrained IoT devices. To
meet this requirement, a firmware image must be divided into sectors, with
each sector encrypted individually using a cipher that does not increase
the size of the resulting ciphertext (i.e., by avoiding the addition of
an authentication tag after each encrypted block).

If an update is aborted while the bootloader is decrypting the newly received
image and swapping the sectors, the bootloader can restart from where it
left off. This technique enhances robustness and performance.

For this purpose, ciphers without integrity protection are employed to
encrypt the firmware image. It is crucial that integrity protection for the
firmware image is provided, and the suit-parameter-image-digest, defined in
{{Section 8.4.8.6 of I-D.ietf-suit-manifest}}, MUST be utilized.

{{RFC9459}} specifies the AES Counter (AES-CTR) mode and AES Cipher Block
Chaining (AES-CBC) ciphers, both of which do not provide integrity protection.
These ciphers are suitable for firmware encryption in IoT devices. However,
for many other scenarios involving software packages, configuration information,
or personalization data, the use of AEAD ciphers is RECOMMENDED.

The following subsections offer additional information on the selection of
initialization vectors (IVs) for use with AES-CBC and AES-CTR in the context
of firmware encryption. A random CEK MUST be used with every plaintexts, as specified
in {{content-key-distribution}}, since the IVs are not random but are instead based on
the slot/sector combination in flash memory. The discussion assumes that the block size
of AES is significantly smaller than the sector size. Typically, flash memory sectors are
measured in KiB, necessitating the decryption of multiple AES blocks to complete the
decryption of an entire sector.

# Complete Examples 

The following manifests illustrate how to deliver an encrypted payload along
with its encryption information to devices.

In the AES-KW examples, HMAC-256 MACs are included, utilizing the following
secret key:

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

The following SUIT manifest instructs a parser to authenticate the manifest
using COSE_Mac0 with HMAC256. It also directs the parser to write and decrypt
the encrypted payload into a component using the suit-directive-write directive.

The SUIT manifest in diagnostic notation (with line breaks added for clarity) is displayed below:

~~~ cbor-diag
{::include-fold examples/suit-manifest-aes-kw-content.diag.signed}
~~~

In hex format, the SUIT manifest is:

~~~ test-vectors
{::include-fold examples/suit-manifest-aes-kw-content.hex.signed}
~~~


## AES Key Wrap Example with Fetch + Copy Directives {#example-AES-KW-copy}

The following SUIT manifest instructs a parser to fetch and store the
encrypted payload. Subsequently, the payload is decrypted and copied into
another component using the suit-directive-copy directive. This approach
is particularly effective for constrained devices with execute-in-place
(XIP) flash memory.

The SUIT manifest in diagnostic notation (with line breaks added for
clarity) is displayed below:

~~~ cbor-diag
{::include-fold examples/suit-manifest-aes-kw.diag.signed}
~~~

The default storage area is defined by the component identifier (see
{{Section 8.4.5.1 of I-D.ietf-suit-manifest}}). In this example,
the component identifier for component #0 is ['plaintext-firmware']
and the file path "/plaintext-firmware" is the expected location.

While parsing the manifest, the behavior of SUIT manifest processor would be

- [L2-L17] authenticates the manifest part on [L18-L68]
- [L22-L25] gets two component identifiers; ['plaintext-firmware'] for component #0, and ['encrypted-firmware'] for component # 1 respectively
- [L29] sets current component index # 1 (the lasting directives target ['encrypted-firmware'])
- [L33-L34] sets source uri parameter "coaps://example.com/encrypted-firmware"
- [L36] fetches content from source uri into ['encrypted-firmware']
- [L39] sets current component index # 0 (the lasting directives target ['plaintext-firmware'])
- [L42-L62] sets SUIT encryption info parameter
- [L63-L64] sets source component index parameter # 1
- [L66] decrypts component # 1 (source component index) and stores the result into component # 0 (current component index)

{{table-manifest-feature}} lists the features from the SUIT manifest specification, which
are re-used by this specification.

| Feature Name                               | Abbr.   | Manifest Ref. |
|--------------------------------------------|---------|---------------|
| component identifier                       | CI      | Sec. 8.4.5.1  |
| (destination) component index              | dst-CI  | Sec. 8.4.10.1 |
| (destination) component slot OPTIONAL param| dst-CS  | Sec. 8.4.8.8  |
| (source) uri OPTIONAL parameter            | src-URI | Sec. 8.4.8.10 |
| source component index OPTIONAL parameter  | src-CI  | Sec. 8.4.8.11 |
{: #table-manifest-feature title="Example Flash Area Layout"}

The resulting state of the SUIT manifest processor is shown in {{table-suit-processor}}.

| Abbreviation  | Plaintext              | Ciphertext                               |
|---------------|------------------------|------------------------------------------|
| CI            | ['plaintext-firmware'] | ['encrypted-firmware']                   |
| dst-CI        | 0                      | 1                                        |
| dst-CS        | N/A                    | N/A                                      |
| src-URI       | N/A                    | "coaps://example.com/encrypted-firmware" |
| src-CI        | 1                      | N/A                                      |
{: #table-suit-processor title="Manifest Processor State"}

In hex format, the SUIT manifest shown above is:

~~~ test-vectors
{::include-fold examples/suit-manifest-aes-kw.hex.signed}
~~~

The encrypted payload (with a line feed added) to be fetched from "coaps://example.com/encrypted-firmware" is:

~~~ test-vectors
{::include-fold examples/encrypted-payload-aes-kw-aes-gcm.hex}
~~~

The previous example does not utilize storage slots. However, it is possible to
implement this functionality for devices that support slots in flash memory. In
the enhanced example below, we reference the slots using [h'00'] and [h'01']. In
this context, the component identifier [h'00'] designates component slot #0.

~~~ cbor-diag
{::include-fold examples/suit-manifest-aes-kw-slot.diag.signed}
~~~

## ES-DH Example with Write + Copy Directives {#example-ES-DH-write}

The following SUIT manifest instructs a parser to authenticate the manifest
using COSE_Sign1 with ES256. It also directs the parser to write and decrypt
the encrypted payload into a component via the suit-directive-write directive.

The SUIT manifest in diagnostic notation (formatted with line breaks for clarity)
is presented below:

~~~ cbor-diag
{::include-fold examples/suit-manifest-es-ecdh-content.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~ test-vectors
{::include-fold examples/suit-manifest-es-ecdh-content.hex.signed}
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
and referred to by the "#dependency-manifest" URI.

The SUIT manifest in diagnostic notation (with line breaks added for
readability) is shown here:

~~~ cbor-diag
{::include-fold examples/suit-manifest-es-ecdh-dependency.diag.signed}
~~~

In hex format, the SUIT manifest is this:

~~~ test-vectors
{::include-fold examples/suit-manifest-es-ecdh-dependency.hex.signed}
~~~

# Operational Considerations

The algorithms outlined in this document assume that the party
responsible for payload encryption:

- shares a key-encryption key (KEK) with the recipient
  (for use with the AES Key Wrap scheme), or
- possesses the  recipient's public key (for use with ES-DH).

Both scenarios necessitate initial communication to distribute
these keys among the involved parties. This interaction can be
facilitated by a device management protocol, as described in
{{RFC9019}}, or may occur earlier in the device lifecycle, such
as during manufacturing or commissioning. In addition to the
keying material, key identifiers and algorithm information must
also be provisioned. This specification does not impose any
requirements on the structure of the key identifier.

In certain situations, third-party companies analyze binaries for
known security vulnerabilities. However, encrypted payloads hinder
this type of analysis. Consequently, these third-party companies
must either be granted access to the plaintext binary before
encryption or be authorized recipients of the encrypted payloads.

# Security Considerations {#sec-cons}

This entire document focuses on security.

It is considered best security practice to use different keys for
different purposes. For instance, the key-encryption key (KEK)
utilized in an AES-KW-based content key distribution method for
encryption should be distinct from the long-term symmetric key
employed for authentication in a communication security protocol.

To further minimize the attack surface, it may be advantageous to
use different long-term keys for encrypting various types of
payloads. For example, KEK_1 could be used with an AES-KW content
key distribution method to encrypt a firmware image, while KEK_2
would encrypt configuration data.

A substantial part of this document focuses on content key
distribution, utilizing two primary methods: AES Key Wrap (AES-KW) and
Ephemeral-Static Diffie-Hellman (ES-DH). The key properties associated
with their deployment are summarized in {{cek-distribution}}.

| Number of<br/>Long-Term<br/>Keys | Number of<br/>Content<br/>Encryption<br/>Keys (CEKs)                  | Use Case                                     | Recommended?         |
|----------------------------------|-----------------------------------------------------------------------|----------------------------------------------|----------------------|
| Same key<br/>for all<br/>devices | Single<br/>CEK per<br/>payload<br/>shared<br/>with all<br/>devies     | Legacy<br/>Usage                             | No, bad<br/>practice |
| One key<br/>per device           | Single<br/>CEK per<br/>payload<br/>shared<br/>with all<br/>devies     | Efficient<br/>Payload<br/>Distribution       | Yes                  |
| One Key<br/>per device           | One CEK<br/>per payload<br/>encryption<br/>transaction<br/>per device | Point-to-<br/>Point Payload<br/>Distribution | Yes                  |
{: #cek-distribution title="Content Key Distribution: Comparison"}

The use of firmware encryption in battery-powered IoT devices introduces the
risk of a battery exhaustion attack. This attack exploits the
high energy cost of flash memory operations. To execute this
attack, the adversary must be able to swap detached payloads
and trick the device into processing an incorrect payload.
Payload swapping is feasible only if there is no communication
security protocol between the device and the distribution
system or if the distribution system itself has been compromised.

While the security features provided by the manifest can detect
this attack and prevent the device from booting with an
incorrectly supplied payload, the energy-intensive flash
operations will have already occurred. As a result, these
operations can diminish the lifespan of the devices, making
battery-powered IoT devices particularly susceptible to such
attacks. For further discussion on IoT devices using flash memory,
see {{flash}}.

Including the digest of the encrypted firmware in the manifest
enables the device to detect a battery exhaustion attack before
energy-consuming decryption and flash memory copy or swap
operations take place.

While the examples in this document use the coaps scheme for payload
retrieval, alternative URI schemes such as coap and http may also
be used. This flexibility is possible because the SUIT manifest
and this extension are not dependent on the TLS layer for security.

Confidentiality, integrity, and authentication are instead ensured
through the SUIT manifest and the extensions defined in this document.

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

~~~ cddl
{::include-fold draft-ietf-suit-firmware-encryption.cddl}
~~~

# Acknowledgements
{: numbered="no"}

We would like to thank Henk Birkholz for his feedback on the CDDL description in this document.
Additionally, we would like to thank Michael Richardson, Dick Brooks, Øyvind Rønningstad, Dave Thaler, Laurence
Lundblade, Christian Amsüss, Ruud Derwig, Martin Thomson. Kris Kwiatkowski, Suresh Krishnan and Carsten Bormann for their review feedback.

We would like to thank the IESG, in particular Deb Cooley, Éric Vyncke and Roman Danyliw, for their help to improve the quality of this document.
