---
title: Encrypted Payloads in SUIT Manifests
abbrev: Encrypted Payloads in SUIT Manifests
docname: draft-ietf-suit-firmware-encryption-13
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
  I-D.isobe-cose-key-thumbprint:

informative:
  RFC9019:
  RFC9124:
  RFC8937:
  RFC5652:
  RFC5280:
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
  
--- abstract

This document specifies techniques for encrypting software, firmware
and personalization data by utilizing the IETF
SUIT manifest. Key agreement is provided by ephemeral-static (ES)
Diffie-Hellman (DH) and AES Key Wrap (AES-KW). ES-DH
uses public key cryptography while AES-KW uses a pre-shared
key-encryption key. Encryption of the plaintext is
accomplished with conventional symmetric key cryptography.

--- middle

#  Introduction

Vulnerabilities with Internet of Things (IoT) devices have raised the
need for a reliable and secure firmware update mechanism that is also
suitable for constrained devices. To protect firmware images the SUIT manifest
format was developed {{I-D.ietf-suit-manifest}}. The SUIT manifest provides a
bundle of metadata about the firmware for an IoT device, where to find 
the firmware image, and the devices to which it applies.

The SUIT information model {{RFC9124}} details the
information that has to be offered by the SUIT manifest format. In addition to
offering protection against modification, which is provided by a digital
signature or a message authentication code, the firmware image may also
be afforded confidentiality using encryption.

Encryption prevents third parties, including attackers, from gaining access to
the firmware binary. Hackers typically need intimate knowledge of the target
firmware to mount their attacks. For example, return-oriented programming (ROP)
{{ROP}} requires access to the binary and encryption makes it much more difficult
to write exploits.

The SUIT manifest provides the data needed for authorized recipients
of the firmware image to decrypt it. The firmware image is encrypted using a
symmetric key.

A symmetric key can be established using a variety of mechanisms; this document
defines two approaches for use with the IETF SUIT manifest, namely:

- Ephemeral-Static (ES) Diffie-Hellman (DH), and
- AES Key Wrap (AES-KW) using a pre-shared key-encryption key (KEK).

OPEN ISSUE: Should KEM algorithms also be supported?

These choices reduce the number of possible key establishment options and thereby
help increase interoperability between different SUIT manifest parser implementations.

While the original motivating use case of this document was firmware encryption, SUIT manifests
may require payloads other than firmware images to experience confidentiality
protection, such as

- software packages,
- personalization data,
- configuration data, and
- machine learning models.
 
Hence, the term payload is used to generically refer to those objects that may be subject to
encryption.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document assumes familiarity with the IETF SUIT manifest {{I-D.ietf-suit-manifest}},
the SUIT information model {{RFC9124}} and the SUIT architecture {{RFC9019}}.

The terms sender and recipient have the following meaning:

* Sender: Role of the entity that sends an encrypted payload.
* Recipient: Role of the entity that receives an encrypted payload.

Additionally, the following abbreviations are used in this document:

* Key Wrap (KW), defined in {{RFC3394}} (for use with AES)
* Key-Encryption Key (KEK) {{RFC3394}}
* Content-Encryption Key (CEK) {{RFC5652}}
* Ephemeral-Static (ES) Diffie-Hellman (DH) {{RFC9052}}

# Architecture {#arch}

{{RFC9019}} describes the architecture for distributing payloads and
manifests from an author to devices. It does, however, not detail the
use of payload encryption.

This document enhances this architecture to support encryption. The author
and the distribution system are logical roles. In some deployments these
roles are separated in different physical entities and in others they are
co-located.

{{arch-fig}} shows the distribution system, which represents the firmware
server and the device management infrastructure. The distribution system is
aware of the individual devices to which a payload has to be delivered. The
author is typically unaware which devices need to receive these payloads.

To apply encryption the sender needs to know the recipient. For AES-KW the
KEK needs to be known and, in case of ES-DH, the sender needs to be in possession
of the public key of the recipient. The DH public key and parameters may be in
the recipient's X.509 certificate {{RFC5280}}.

If the author delegates the task of identifying the recipients of the payloads
to the distribution system, it needs to trust it with the appropriate
protection of the plaintext firmware image before encryption is performed.

~~~
                                           +----------+
                                           |          |
                                           |  Author  |
                                           |          |
 +----------+                              +----------+
 |  Device  |---+                               |
 |          |   |                               | Firmware +
 |          |   |                               | Manifest
 +----------+   |                               |
                |                               |
                |                        +--------------+
                |                        |              |
 +----------+   |  Firmware + Manifest   | Distribution |
 |  Device  |---+------------------------|    System    |
 |          |   |                        |              |
 |          |   |                        |              |
 +----------+   |                        +--------------+
                |
                |
 +----------+   |
 |  Device  +---+
 |          |
 |          |
 +----------+
~~~
{: #arch-fig title="Firmware Encryption Architecture."}

To offer confidentiality protection two deployment variants need to be
supported:

* The author, as the sender, transmits the encrypted payload to a single
  device, or to multiple devices. The device(s) perform decryption and
  act as recipients.

* The author treats the distribution system as the initial recipient. Then,
  the distribution system decrypts and re-encrypts the payload for consumption
  by the device (or the devices). Delegating the task of re-encrypting
  the payload to the distribution system offers flexiblity when the number
  of devices that need to receive encrypted payloads changes dynamically
  or when updates to KEKs or recipient public keys are necessary. As a downside,
  the author needs to trust the distribution system with performing the
  re-encryption of the payload.

For both variants the key distribution data, which is embedded inside the
COSE_Encrypt structure, is included in the SUIT manifest.

# Encryption Extensions {#parameters}

This specification introduces a new extension to the SUIT_Parameters structure.

The SUIT encryption info parameter (called suit-parameter-encryption-info),
see {{parameter-fig}}, contains key distribution information. It is carried
inside the suit-directive-override-parameters or the suit-directive-set-parameters
structure. The content of the SUIT_Encryption_Info structure is explained in
{{AES-KW}} (for AES-KW) and {{ES-DH}} (for ECDH-ES). An implementation claiming
conformance with this specification must implement support for this parameter.
A device may, however, support only one of the available key distribution techniques.

~~~
SUIT_Parameters //= (suit-parameter-encryption-info
    => bstr .cbor SUIT_Encryption_Info)

suit-parameter-encryption-info   = [TBD1: Proposed 19]
~~~
{: #parameter-fig title="CDDL of the SUIT_Parameters Extension."}

# Extended Directives

This specification extends these directives:

- Directive Write (suit-directive-write) to decrypt the content specified by
suit-parameter-content with suit-parameter-encryption-info.
- Directive Copy (suit-directive-copy) to decrypt the content of the component
specified by suit-parameter-source-component with suit-parameter-encryption-info.

Examples of the two extensioned directives are shown in {{encryption-info-consumed-with-write}}
and in {{encryption-info-consumed-with-copy}}.

~~~
/ directive-override-parameters / 20, {
  / parameter-content / 18: h'EA1CED',
  / parameter-encryption-info / 19: h'D860E1A1F0'
},
/ directive-write / 18, 15
/ NOTE: decrypt h'EA1CED' using h'D860E1A1F0' /
/ NOTE: plaintext payload is stored into component #0 /
~~~
{: #encryption-info-consumed-with-write title="Example showing the Extended suit-directive-write."}

~~~
/ directive-set-component-index / 12, 1,
/ directive-override-parameters / 20, {
  / parameter-uri / 21: "http://example.com/encrypted.bin",
},
/ directive-fetch / 21, 15,
/ NOTE: encrypted payload is stored into component #1 /
/ directive-set-component-index / 12, 0,
/ directive-override-parameters / 20, {
  / parameter-source-component / 22: 1,
  / parameter-encryption-info / 19: h'D860E1A1F0'
},
/ directive-copy / 22, 15
/ NOTE: decrypt component #1 using h'D860E1A1F0' /
/ NOTE: plaintext payload is stored into component #0 /
~~~
{: #encryption-info-consumed-with-copy title="Example showing the Extended suit-directive-copy."}

# Content Key Distribution Methods

The sub-sections below describe two content key distribution mechanisms,
namely AES Key Wrap (AES-KW) and Ephemeral-Static Diffie-Hellman (ES-DH).
Other mechanisms are supported by COSE and may be supported via enhancements
to this specification.

When an encrypted firmware image is sent to multiple recipients, there
are different deployment options. To explain these options we use the
following notation:

- KEK(R1,S) refers to a KEK shared between recipient R1 and the sender S.
The KEK, as a concept, is used by AES Key Wrap.
- CEK(R1,S) refers to a CEK shared between R1 and S.
- CEK(*,S) or KEK(*,S) are used when a single CEK or a single KEK is shared
with all authorized recipients by a given sender S in a certain context.
- ENC(plaintext, k) refers to the encryption of plaintext with a key k.
- KEK_i or CEK_i refers to the i-th instance of the KEK or CEK, respectively.

## Content Key Distribution with AES Key Wrap {#AES-KW}

### Introduction

The AES Key Wrap (AES-KW) algorithm is described in RFC 3394 {{RFC3394}}, and
can be used to encrypt a randomly generated content-encryption key (CEK)
with a pre-shared key-encryption key (KEK). The COSE conventions for using
AES-KW are specified in Section 8.5.2 of {{RFC9052}} and in Section 6.2.1 of
{{RFC9053}}. The encrypted CEK is carried in the COSE\_recipient structure
alongside the information needed for AES-KW. The COSE\_recipient structure,
which is a substructure of the COSE\_Encrypt structure, contains the CEK
encrypted by the KEK. 

The COSE\_Encrypt structure conveys information for encrypting the payload,
which includes information like the algorithm and the IV, even though the
payload is not embedded in the COSE_Encrypt.ciphertext itself since it
conveyed as detached content.

### Deployment Options

There are three deployment options for use with AES Key Wrap for payload
encryption:

- If all authorized recipients have access to the KEK, a single
COSE\_recipient structure contains the encrypted CEK. The sender executes
the following steps:

~~~
      Fetch KEK(*,S)
      Generate CEK
      ENC(CEK,KEK)
      ENC(payload,CEK)
~~~

- If recipients have different KEKs, then multiple COSE\_recipient structures
are included but only a single CEK is used. Each COSE\_recipient structure
contains the CEK encrypted with the KEKs appropriate for a given recipient.
The benefit of this approach is that the payload is encrypted only once with
a CEK while there is no sharing of the KEK across recipients. Hence, authorized
recipients still use their individual KEK to decrypt the CEK and to subsequently
obtain the plaintext. The steps taken by the sender are:

~~~
      Generate CEK
      for i=1 to n {
         Fetch KEK_i(Ri, S)
         ENC(CEK, KEK_i)
      }
      ENC(payload,CEK)
~~~

- The third option is to use different CEKs encrypted with KEKs of
authorized recipients. Assume there are n recipients with their unique KEKs -
KEK_1(R1, S),..., KEK_n(Rn, S). The sender needs to make the following steps:

~~~
      for i=1 to n {
         Fetch KEK_i(Ri, S)
         Generate CEK_i
         ENC(CEK_i, KEK_i)
         ENC(payload,CEK_i)
      }
~~~

This approach is appropriate when no benefits can be gained from encrypting
and transmitting payloads only once.

### CDDL

The CDDL for the COSE_Encrypt_Tagged structure is shown in {{cddl-aeskw}}.

~~~
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)
 
SUIT_Encryption_Info = COSE_Encrypt_Tagged

COSE_Encrypt = [
  protected   : bstr .cbor outer_header_map_protected,
  unprotected : outer_header_map_unprotected,
  ciphertext  : bstr / nil,
  recipients  : [ + COSE_recipient ]
]

outer_header_map_protected =
{
    1 => int,         ; algorithm identifier
  * label => values   ; extension point
}

outer_header_map_unprotected = 
{
    5 => bstr,        ; IV
  * label => values   ; extension point
}

COSE_recipient = [
  protected   : bstr .size 0,
  unprotected : recipient_header_map,
  ciphertext  : bstr        ; CEK encrypted with KEK
]

recipient_header_map = 
{
    1 => int,         ; algorithm identifier
    4 => bstr,        ; key identifier
  * label => values   ; extension point
}
~~~
{: #cddl-aeskw title="CDDL for AES-KW-based Content Key Distribution"}

Note that the AES-KW algorithm, as defined in Section 2.2.3.1 of {{RFC3394}},
does not have public parameters that vary on a per-invocation basis. Hence,
the protected header in the COSE_recipient structure is a byte string
of zero length.

The COSE specification requires a consistent byte stream for the authenticated
data structure to be created. This structure is shown in {{cddl-enc-aeskw}}.

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
It is important to note that there are two protected fields shown
in {{cddl-aeskw}}:

- one in the COSE_Encrypt structure, and
- a second one in the COSE_recipient structure.

The value of the external_aad MUST be set to a null value (major type 7,
value 22).

### Example

This example uses the following parameters:

- Algorithm for payload encryption: AES-GCM-128
- Algorithm id for key wrap: A128KW
- IV: 0x26, 0x68, 0x23, 0x06, 0xd4, 0xfb, 0x28, 0xca, 0x01, 0xb4, 0x3b, 0x80
- KEK: "aaaaaaaaaaaaaaaa"
- KID: "kid-1"
- Plaintext firmware (txt): "This is a real firmware image."
  (in hex): 546869732069732061207265616C206669726D7761726520696D6167652E

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
D8608443A10101A1054C26682306D4FB28CA01B43B80F68340A2012204456B69642D
315818AF09622B4F40F17930129D18D0CEA46F159C49E7F68B644D
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in
{{aeskw-example}}. 

~~~
96([
  / protected: / << {
    / alg / 1: 1 / AES-GCM-128 /
  } >>,
  / unprotected: / {
    / IV / 5: h'1de460e8b5b68d7222c0d6f20484d8ab'
  },
  / payload: / null / detached ciphertext /,
  / recipients: / [
    [
      / protected: / << {
      } >>,
      / unprotected: / {
        / alg / 1: -3 / A128KW /,
        / kid / 4: 'kid-1'
      },
      / payload: CEK encrypted with KEK /
      h'a86200e4754733e4c00fc08c6a72cc1996e129922eab504f'
    ]
  ]
])
~~~
{: #aeskw-example title="COSE_Encrypt Example for AES Key Wrap"}

The CEK, in hex format, was "4C805F1587D624ED5E0DBB7A7F7FA7EB".
The encrypted firmware (with a line feed added) was:

~~~ 
A8B6E61EF17FBAD1F1BF3235B3C64C06098EA512223260
F9425105F67F0FB6C92248AE289A025258F06C2AD70415
~~~

## Content Key Distribution with Ephemeral-Static Diffie-Hellman {#ES-DH}

### Introduction

Ephemeral-Static Diffie-Hellman (ES-DH) is a scheme that provides public key
encryption given a recipient's public key. There are multiple variants
of this scheme; this document re-uses the variant specified in Section 8.5.5
of {{RFC9052}}.

The following two layer structure is used:

- Layer 0: Has a content encrypted with the CEK. The content may be detached.
- Layer 1: Uses the AES Key Wrap algorithm to encrypt a randomly generated
CEK with the KEK derived with ECDH Ephemeral-Static whereby the resulting symmetric
key is fed into the HKDF-based key derivation function.

As a result, the two layers combine ECDH-ES with AES-KW and HKDF. An example is
given in {{esdh-example}}.

### Deployment Options

There are two deployment options with this approach. We assume that recipients
are always configured with a device-unique public / private key pair.

- A sender wants to transmit a payload to multiple recipients. All recipients
shall receive the same encrypted payload, i.e. the same CEK is used.
One COSE\_recipient structure per recipient is used and it contains the
CEK encrypted with the KEK. To generate the KEK each COSE\_recipient structure
contains a COSE_recipient_inner structure to carry the sender's emphemeral key
and an identifier for the recipients public key.

The steps taken by the sender are:

~~~
      Generate CEK
      for i=1 to n {
         Generate KEK_i(Ri, S) using ES-DH
         ENC(CEK, KEK_i)
      }
      ENC(payload,CEK)
~~~

- The alternative is to encrypt a payload with a different CEK for each
recipient. Assume there are KEK_1(R1, S),..., KEK_n(Rn, S) have been generated
for the different recipients using ES-DH. The following steps needs to be made
by the sender:

~~~
      for i=1 to n {
         Generate KEK_i(Ri, S) using ES-DH
         Generate CEK_i
         ENC(CEK_i, KEK_i)
         ENC(payload,CEK_i)
      }
~~~

This results in n-manifests. This approach is useful when payloads contain
information unique to a device. The encryption operation effectively becomes
ENC(payload_i,CEK_i).

### CDDL

The CDDL for the COSE_Encrypt_Tagged structure is shown in {{cddl-esdh}}.

~~~
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)
 
SUIT_Encryption_Info = COSE_Encrypt_Tagged

COSE_Encrypt = [
  protected   : bstr .cbor outer_header_map_protected,
  unprotected : outer_header_map_unprotected,
  ciphertext  : bstr / nil,
  recipients  : [ + COSE_recipient ]
]

outer_header_map_protected =
{
    1 => int,         ; algorithm identifier
  * label => values   ; extension point
}

outer_header_map_unprotected = 
{
    5 => bstr,        ; IV
  * label => values   ; extension point
}

COSE_recipient = [
  protected   : bstr .cbor recipient_header_pr_map,
  unprotected : recipient_header_unpr_map,
  ciphertext  : bstr        ; CEK encrypted with KEK
]

recipient_header_pr_map = 
{
    1 => int,         ; algorithm identifier for key wrap
  * label => values   ; extension point
}

recipient_header_unpr_map = 
{
   -1 => COSE_Key,    ; ephemeral public key for the sender
    4 => bstr,        ; identifier of the recipient public key
  * label => values   ; extension point
}
~~~
{: #cddl-esdh title="CDDL for ES-DH-based Content Key Distribution"}

### Context Information Structure

The context information structure is used to ensure that the derived keying material 
is "bound" to the context of the transaction. This specification re-uses the structure
defined in Section 5.2 of RFC 9053 and tailors it accordingly.

The following information elements are bound to the context:

* the hash of the public key of the sender, 
* the hash of the public key of the recipient,
* the protocol employing the key-derivation method,
* information about the utilized algorithms
  (including the payload encryption algorithms,
   the content key encryption algorithm,
   and the key length).

The following fields in {{cddl-context-info}} require an explantation:

- The identity fields in the PartyInfoSender and the PartyInfoRecipient structures
contain the COSE_Key Thumbprint of the public keys of the sender and the recipient,
respectively. The details for computing these thumbprints are described in 
{{I-D.isobe-cose-key-thumbprint}}.

- The COSE_KDF_Context.AlgorithmID field contains the value found in the
alg field of the protected header in the COSE_Encrypt structure. This is the content
encryption algorithm identifier.

- The COSE_KDF_Context.SuppPubInfo.keyDataLength field contains the key length
of the algorithm in the alg field of the protected header in the COSE_Encrypt structure 
expressed as the number of bits.

- The COSE_KDF_Context.SuppPubInfo.other field captures the protocol in
which the ES-DH content key distribution algorithm is used and it is set to
the constant string "SUIT Payload Encryption".

- The COSE_KDF_Context.SuppPubInfo.protected field serializes the content 
of the recipient_header_pr_map field, which contains the content key distribution
algorithm identifier.

~~~
PartyInfoSender = (
    identity : bstr,
    nonce : nil,
    other : bstr .size 0
)

PartyInfoRecipient = (
    identity : bstr,
    nonce : nil,
    other : bstr .size 0
)

COSE_KDF_Context = [
    AlgorithmID : int,
    PartyUInfo : [ PartyInfoSender ],
    PartyVInfo : [ PartyInfoRecipient ],
    SuppPubInfo : [
        keyDataLength : uint,
        protected : bstr .cbor recipient_header_pr_map,
        other: bstr "SUIT Payload Encryption"
    ],
    SuppPrivInfo : bstr .size 0
]
~~~
{: #cddl-context-info title="CDDL for COSE_KDF_Context Structure"}

 
### Example

This example uses the following parameters:

- Algorithm for payload encryption: AES-GCM-128
- IV: 0x26, 0x68, 0x23, 0x06, 0xd4, 0xfb,
      0x28, 0xca, 0x01, 0xb4, 0x3b, 0x80
- Algorithm for content key distribution: ECDH-ES + A128KW
- KID: "kid-1"
- Plaintext: "This is a real firmware image."
- Firmware (hex):
  546869732069732061207265616C206669726D7761726520696D6167652E

The COSE_Encrypt structure, in hex format, is (with a line break inserted):

~~~
D8608443A10101A1054C26682306D4FB28CA01B43B805823F21AC5881CD6FC45754
C65790F806C81A57B8D96C1988233BF40F670172405B5F107FD8444A101381C44A1
01381CA220A401022001215820415A8ED270C4B1F10B0A2D42B28EE6028CE25D745
52CB4291A4069A2E989B0F6225820CCC9AAF60514B9420C80619A4FF068BC1D7762
5BA8C90200882F7D5B73659E7604456B69642D315818B37CCD582696E5E62E5D93A
555E9072687D6170B122322EE
~~~

The resulting COSE_Encrypt structure in a diagnostic format is shown in 
{{esdh-example}}. 

~~~
96(
  [
   / protected / h'a10101' / {
       \ alg \ 1:1 \ AES-GCM-128 \
     } / ,
   / unprotected / {
     / iv / 5:h'26682306D4FB28CA01B43B80'
     },
   / encrypted firmware /
    h'F21AC5881CD6FC45754C65790F806C81A57
      B8D96C1988233BF40F670172405B5F107FD',
    [
       / protected / h'A101381C' / {
           \ alg \ 1:-29 \ ECDH-ES + A128KW \
         } / ,
         h'A101381C',
       / unprotected / {
             / ephemeral / -1: {
                   / kty / 1:2,
                   / crv / -1:1,
                   / x / -2:h'415A8ED270C4B1F10B0A2D42B28EE602
                              8CE25D74552CB4291A4069A2E989B0F6',
                   / y / -3:h'CCC9AAF60514B9420C80619A4FF068BC
                              1D77625BA8C90200882F7D5B73659E76'
                 },
                 / kid / 4:'kid-1'
        },
        / ciphertext - CEK encrypted with KEK /
        h'B37CCD582696E5E62E5D93A555E9072687D6170B122322EE'
    ]
  ]
)
~~~
{: #esdh-example title="COSE_Encrypt Example for ES-DH"}

# Firmware Updates on IoT Devices with Flash Memory

Flash memory on microcontrollers is a type of non-volatile memory that erases
data in units called blocks, pages or sectors and re-writes data at byte level
(often 4-bytes).
Flash memory is furthermore segmented into different memory regions, which store
the bootloader, different versions of firmware images (in so-called slots),
and configuration data. {{image-layout}} shows an example layout of a
microcontroller flash area. The primary slot contains the firmware image to be
executed by the bootloader, which is a common deployment on devices that do
not offer the concept of position independent code.

When the encrypted firmware image has been transferred to the device, it will
typically be stored in a staging area, in the secondary slot in our example.

At the next boot, the bootloader will recognize a new firmware image in the
secondary slot and will start decrypting the downloaded image sector-by-sector
and will swap it with the image found in the primary slot.

The swap should only take place after the signature on the plaintext is verified.
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
image is often referred as A/B approach. A/B refers to the two slots involved.
Two slots are used to allow the update to be reversed in case the newly obtained
firmware image fails to boot. This approach adds robustness to the firmware
update procedure.

Since the image in primary slot is available in cleartext it may need to
re-encrypted it before copying it to the secondary slot. This may be necessary
when the secondary slot has different access permissions or when the staging
area is located in an off-chip flash memory and therefore more vulnerable to
physical attacks. Note that this description assumes that the processor does
not execute encrypted memory (i.e. using on-the-fly decryption in hardware).

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

For this purpose ciphers without integrity protection are used to encrypt the
firmware image. Integrity protection for the firmware image must, however, be
provided and the suit-parameter-image-digest, defined in Section 8.4.8.6 of
{{I-D.ietf-suit-manifest}}, MUST be used.

{{I-D.ietf-cose-aes-ctr-and-cbc}} registers AES Counter mode (AES-CTR) and
AES Cipher Block Chaining (AES-CBC) ciphers that do not offer integrity protection.
These ciphers are useful for the use cases that require firmware encryption on IoT
devices. For many other use cases where software packages, configuration information
or personalization data needs to be encrypted, the use of Authenticated Encryption
with Additional Data (AEAD) ciphers is preferred.

The following sub-sections provide further information about the initialization vector
(IV) selection for use with AES-CBC and AES-CTR in the firmware encryption context. An
IV MUST NOTE be re-used when the same key is used. For this application, the IVs are
not random but rather based on the slot/sector-combination in flash memory. The
text below assumes that the block-size of AES is (much) smaller than sector size. The
typical sector-size of flash memory is in the order of KiB. Hence, multiple AES blocks
need to be decrypted until an entire sector is completed.

## AES-CBC

In AES-CBC a single IV is used for encryption of firmware belonging to a single sector
since individual AES blocks are chained toghether, as shown in {{aes-cbc-fig}}. The
numbering  of sectors in a slot MUST start with zero (0) and MUST increase by one with
every sector till the end of the slot is reached. The IV follows this numbering.

For example, let us assume the slot size of a specific flash controller on an IoT device
is 64 KiB, the sector size 4096 bytes (4 KiB) and AES-128-CBC uses an AES-block size of
128 bit (16 bytes). Hence, sector 0 needs 4096/16=256 AES-128-CBC operations using IV 0.
If the firmware image fills the entire slot then that slot contains 16 sectors, i.e. IVs
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

# Complete Examples 

The following manifests examplify how to deliver encrypted firmware and its
encryption info to devices.

The examples are signed using the following ECDSA secp256r1 key:

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

The following SUIT manifest requests a parser to write and to decrypt the
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
payload and to stores it. Then, the payload is decrypt and stored into
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

# Security Considerations {#sec-cons}

The algorithms described in this document assume that the party performing payload encryption

- shares a key-encryption key (KEK) with the recipient (for use with the AES Key Wrap scheme), or
- is in possession of the public key of the recipient (for use with ECDH-ES).

Both cases require some upfront communication interaction. This interaction is likely provided by
an device management solution, as described in {{RFC9019}}.

To provide high security for AES Key Wrap it is important that the KEK is of high entropy,
and that implementations protect the KEK from disclosure. Compromise of the KEK may result
in the disclosure of all key data protected with that KEK.

Since the CEK is randomly generated, it must be ensured that the guidelines for random number
generation in {{RFC8937}} are followed.

In some cases third party companies analyse binaries for known security vulnerabilities. With
encrypted payloads this type of analysis is prevented. Consequently, these third party
companies either need to be given access to the plaintext binary before encryption or they need
to become authorized recipients of the encrypted payloads. In either case, it is necessary to
explicitly consider those third parties in the software supply chain when such a binary analysis
is desired.

#  IANA Considerations

IANA is asked to add two values to the SUIT_Parameters registry established by 
{{I-D.ietf-suit-manifest}}.

~~~
Label      Name                 Reference
-----------------------------------------
TBD1       Encryption Info      Section 4
~~~

[Editor's Note: 
 - TBD1: Proposed 19
]

--- back

# Acknowledgements

We would like to thank Henk Birkholz for his feedback on the CDDL description in this document.
Additionally, we would like to thank Michael Richardson, Øyvind Rønningstad, Dave Thaler, Laurence
Lundblade, and Carsten Bormann for their review feedback. Finally, we would like to thank Dick Brooks for
making us aware of the challenges firmware encryption imposes on binary analysis.


 

