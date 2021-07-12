---
title: Firmware Encryption with SUIT Manifests
abbrev: Firmware Encryption
docname: draft-ietf-suit-firmware-encryption-01
category: std

ipr: pre5378Trust200902
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
       organization: Arm Limited
       email: hannes.tschofenig@arm.com

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


normative:
  I-D.ietf-suit-manifest:
  RFC2119:
  RFC3394:
  RFC8152:
  RFC8174:
  RFC3394:
  I-D.irtf-cfrg-hpke:
  I-D.ietf-cose-rfc8152bis-algs:
  
informative:
  RFC9019:
  I-D.ietf-suit-information-model:
  RFC8937:
  RFC2630:
  RFC4949:
  
--- abstract

This document specifies a firmware update mechanism where the
firmware image is encrypted.  This mechanism uses the IETF 
SUIT manifest with key establishment provided by the hybrid
public-key encryption (HPKE) scheme or AES Key Wrap (AES-KW) with
a pre-shared key-encryption key.  In either case, AES-GCM or 
AES-CCM is used for firmware encryption.

--- middle

#  Introduction

Vulnerabilities with Internet of Things (IoT) devices have raised the
need for a reliable and secure firmware update mechanism that is also
suitable for constrained devices. To protect firmware images the SUIT manifest
format was developed {{I-D.ietf-suit-manifest}}. The SUIT manifest provides a 
bundle of metadata about the firmware for an IoT device, where to find 
the firmware image, and the devices to which it applies.

The SUIT information model {{I-D.ietf-suit-information-model}} details the
information that has to be offered by the SUIT manifest format. In addition to
offering protection against modification, which is provided by a digital
signature or a message authentication code, the firmware image may also 
be afforded confidentiality using encryption.

Encryption prevents third parties, including attackers, from gaining access to
the firmware image. For example, return-oriented programming (ROP) requires 
intimate knowledge of the target firmware and encryption makes this 
approach much more difficult to exploit. The SUIT manifest provides the 
data needed for authorized recipients of the firmware image to decrypt it.

A symmetric cryptographic key is established for encryption and decryption, and 
that key can be applied to a SUIT manifest, firmware images, or personalization
data, depending on the encryption choices of the firmware author. This symmetric key
can be established using a variety of mechanisms; this document defines two 
approaches for use with the IETF SUIT manifest.  Key establishment can be
provided by the hybrid public-key encryption (HPKE) scheme or AES Key Wrap
(AES-KW) with a pre-shared key-encryption key.  These choices reduce the
number of possible key establishment options and thereby help increase 
interoperability between different SUIT manifest parser implementations. 

The document also contains a number of examples for developers.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document assumes familiarity with the IETF SUIT manifest {{I-D.ietf-suit-manifest}}
and the SUIT architecture {{RFC9019}}.

In context of encryption, the terms "recipient" and "firmware consumer" 
are used interchangeably.

Additionally, the following abbreviations are used in this document: 

* Key Wrap (KW), defined in RFC 3394 {{RFC3394}} for use with AES.
* Key-encryption key / key-encrypting key (KEK), a term defined in RFC 4949 {{RFC4949}}. 
* Content-encryption key (CEK), a term defined in RFC 2630 {{RFC2630}}.
* Hybrid Public Key Encryption (HPKE), defined in {{I-D.irtf-cfrg-hpke}}.

# AES Key Wrap

The AES Key Wrap (AES-KW) algorithm is described in RFC 3394 {{RFC3394}}, and
it can be used to encrypt a randomly generated content-encryption key (CEK)
with a pre-shared key-encryption key (KEK). The COSE conventions for using
AES-KW are specified in Section 12.2.1 of {{RFC8152}}.  The encrypted CEK is
carried in the COSE\_recipient structure alongside the information needed for 
AES-KW. The COSE\_recipient structure, which is a substructure of the 
COSE\_Encrypt structure, contains the CEK encrypted by the KEK. 

When the 
firmware image is encrypted for use by multiple recipients, there are three 
options: 

- If all of authorized recipients have access to the KEK, a single 
COSE\_recipient structure contains the encrypted CEK. 

- If recipients have different KEKs, then the COSE\_recipient structure 
may contain the same CEK encrypted with many different KEKs. The benefit 
of this approach is that the firmware image is encrypted only once with 
the CEK while the authorized recipients still need to use their 
individual KEKs to obtain the plaintext.

- The last option is to use different CEKs encrypted with KEKs of the 
authorized recipients. This is appropriated when no benefits can be gained
from encrypting and transmitting firmware images only once. For example, 
firmware images may contain information unique to a device instance.  

Note that the AES-KW algorithm, as defined in Section 2.2.3.1 of {{RFC3394}}, 
does not have public parameters that vary on a per-invocation basis. Hence, 
the protected structure in the COSE_recipient is a byte string of zero length. 

The COSE\_Encrypt conveys information for encrypting the firmware image, 
which includes information like the algorithm and the IV, even though the 
firmware image is not embedded in the COSE_Encrypt.ciphertext itself since 
it conveyed as detached content.

The CDDL for the COSE_Encrypt_Tagged structure is shown in {{cddl-aeskw}}. 

~~~
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)
 
SUIT_Encryption_Info = COSE_Encrypt_Tagged

COSE_Encrypt = [
  protected   : bstr .cbor outer_header_map_protected,
  unprotected : outer_header_map_unprotected,
  ciphertext  : null,                  ; because of detached ciphertext
  recipients  : [ + COSE_recipient ]
]

outer_header_map_protected =
{
    1 => int,         ; algorithm identifier
  * label =values     ; extension point
}

outer_header_map_unprotected = 
{
    5 => bstr,        ; IV
  * label =values     ; extension point
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
  * label =values     ; extension point
}
~~~
{: #cddl-aeskw title="CDDL for AES Key Wrap-based Firmware Encryption"}

The COSE specification requires a consistent byte stream for the
authenticated data structure to be created, which is shown in
{{cddl-enc-aeskw}}.

~~~    
       Enc_structure = [
         context : "Encrypt",
         protected : empty_or_serialized_map,
         external_aad : bstr
       ]
~~~
{: #cddl-enc-aeskw title="CDDL for Enc_structure Data Structure"}

As shown in {{cddl-aeskw}}, there are two protected fields: one 
protected field in the COSE_Encrypt structure and a second one in
the COSE_recipient structure. The 'protected' field in the Enc_structure, 
see {{cddl-enc-aeskw}}, refers to the content of the protected 
field from the COSE_Encrypt structure, not to the protected 
field of the COSE_recipient structure. 

The value of the external_aad is set to null.

The following example illustrates the use of the AES-KW algorithm with AES-128.

We use the following parameters in this example: 

- IV: 0x26, 0x68, 0x23, 0x06, 0xd4, 0xfb, 0x28, 0xca, 0x01, 0xb4, 0x3b, 0x80
- KEK: "aaaaaaaaaaaaaaaa"
- KID: "kid-1"
- Plaintext Firmware: "This is a real firmware image."
- Firmware (hex): 546869732069732061207265616C206669726D7761726520696D6167652E

The COSE_Encrypt structure in hex format is (with a line break inserted):

~~~
D8608443A10101A1054C26682306D4FB28CA01B43B80F68340A2012204456B69642D
315818AF09622B4F40F17930129D18D0CEA46F159C49E7F68B644D
~~~

The resulting COSE_Encrypt structure in a dignostic format is shown in {{aeskw-example}}. 

~~~
96(
    [
        // protected field with alg=AES-GCM-128
        h'A10101', 
        {
           // unprotected field with iv
           5: h'26682306D4FB28CA01B43B80'
        }, 
        // null because of detached ciphertext
        null, 
        [ // recipients array
           h'', // protected field
           {    // unprotected field
              1: -3,            // alg=A128KW 
              4: h'6B69642D31'  // key id
           }, 
           // CEK encrypted with KEK
           h'AF09622B4F40F17930129D18D0CEA46F159C49E7F68B644D'
        ]
    ]
)
~~~
{: #aeskw-example title="COSE_Encrypt Example for AES Key Wrap"}

The CEK was "4C805F1587D624ED5E0DBB7A7F7FA7EB" and the encrypted firmware was:

~~~ 
A8B6E61EF17FBAD1F1BF3235B3C64C06098EA512223260
F9425105F67F0FB6C92248AE289A025258F06C2AD70415
~~~

# Hybrid Public-Key Encryption (HPKE)

Hybrid public-key encryption (HPKE) {{I-D.irtf-cfrg-hpke}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key.

For use with firmware encryption the scheme works as follows: The firmware
author uses HPKE, which internally utilizes a non-interactive ephemeral-static
Diffie-Hellman exchange to derive a shared secret, which is then used to 
encrypt plaintext. 

In the firmware encryption scenario, the plaintext passed to HPKE for encryption 
is the randomly generated CEK. The output of the HPKE operation is therefore 
the encrypted CEK along with HPKE encapsulated key (i.e. the ephemeral ECDH 
public key of the author). The CEK is then used to encrypt the firmware.

Only the holder of recipient's private key can decapsulate the CEK to decrypt the 
firmware. Key generation is influced by additional parameters, such as 
identity information.

This approach allows all recipients to use the same CEK to encrypt the 
firmware image, in case there are multiple recipients, to fulfill a requirement for 
the efficient distribution of firmware images using a multicast or broadcast protocol. 

The CDDL for the COSE_Encrypt structure as used with HPKE is shown in {{cddl-hpke}}.

~~~
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)
 
SUIT_Encryption_Info = COSE_Encrypt_Tagged

COSE_Encrypt = [
  protected   : bstr .cbor header_map, ; must contain alg
  unprotected : header_map,            ; must contain iv
  ciphertext  : null,                  ; because of detached ciphertext
  recipients  : [ + COSE_recipient_outer ]
]

COSE_recipient_outer = [
  protected   : bstr .size 0,
  unprotected : header_map, ; must contain alg
  ciphertext  : bstr        ; CEK encrypted based on HPKE algo
  recipients  : [ + COSE_recipient_inner ]  
]

COSE_recipient_inner = [
  protected   : bstr .cbor header_map, ; must contain alg
  unprotected : header_map, ; must contain kid, 
  ciphertext  : bstr        ; CEK encrypted based on HPKE algo
  recipients  : null
]

header_map = {
  Generic_Headers,
  * label =values,
}

Generic_Headers = (
    ? 1 => int,         ; algorithm identifier
    ? 2 => crv,         ; EC identifier
    ? 4 => bstr,        ; key identifier
    ? 5 => bstr         ; IV
)
~~~
{: #cddl-hpke title="CDDL for HPKE-based COSE_Encrypt Structure"}

The COSE_Encrypt structure in {{cddl-hpke}} requires the 
encrypted CEK and the ephemeral public key of the firmare author to be
generated. This is accomplished with the HPKE encryption function as 
shown in {{hpke-encryption}}.

~~~
    CEK = random()
    pkR = DeserializePublicKey(recipient_public_key)
    info = "cose hpke" || 0x00 || COSE_KDF_Context
    enc, context = SetupBaseS(pkR, info)
    ciphertext = context.Seal(null, CEK)
~~~
{: #hpke-encryption title=HPKE-based Encryption"}

Legend: 

- The functions DeserializePublicKey(), SetupBaseS() and Seal() are 
defined in HPKE {{I-D.irtf-cfrg-hpke}}. 

- CEK is a random byte sequence of keysize length whereby keysize 
corresponds to the size of the indicated symmetric encryption algorithm 
used for firmware encryption. For example, AES-128-GCM requires a 16 byte 
key. The CEK would therefore be 16 bytes long. 

- 'recipient_public_key' represents the public key of the recipient. 

- 'info' is a data structure described below used as input to the key 
derivation internal to the HPKE algorithm. In addition to the constant 
prefix, the COSE_KDF_Context structure is used. The COSE_KDF_Context is 
shown in {{cddl-cose-kdf}}. 

The result of the above-described operation is the encrypted CEK (denoted 
as ciphertext) and the enc - the HPKE encapsulated key (i.e. the ephemeral 
ECDH public key of the author).

~~~
PartyInfo = (
   identity : bstr,
   nonce : nil,
   other : nil
)

COSE_KDF_Context = [
   AlgorithmID : int,
   PartyUInfo : [ PartyInfo ],
   PartyVInfo : [ PartyInfo ],
   SuppPubInfo : [
       keyDataLength : uint,
       protected : empty_or_serialized_map
   ],
]
~~~
{: #cddl-cose-kdf title="COSE_KDF_Context Data Structure"}

Notes: 

- PartyUInfo.identity corresponds to the kid found in the 
COSE_Sign_Tagged or COSE_Sign1_Tagged structure (when a digital 
signature is used). When utilizing a MAC, then the kid is found in 
the COSE_Mac_Tagged or COSE_Mac0_Tagged structure.

- PartyVInfo.identity corresponds to the kid used for the respective 
recipient from the inner-most recipients array.

- The value in the AlgorithmID field corresponds to the alg parameter 
in the protected structure in the inner-most recipients array. 

- keyDataLength is set to the number of bits of the desired output value.

- protected refers to the protected structure of the inner-most array. 

The author encrypts the firmware using the CEK with the selected algorithm. 

The recipient decrypts the encrypted CEK, using two input parameters: 

- the private key skR corresponding to the public key pkR used by the author 
when creating the manifest. 
- the HPKE encapsulated key (i.e. ephemeral ECDH public key) created by the 
author. 

If the HPKE operation is successful, the recipient obtains the CEK and can decrypt the 
firmware.

{{hpke-decryption}} shows the HPKE computations performed by the recipient for decryption.

~~~
    info = "cose hpke" || 0x00 || COSE_KDF_Context
    context = SetupBaseR(ciphertext, skR, info)
    CEK = context.Open(null, ciphertext)
~~~
{: #hpke-decryption title=HPKE-based Decryption"}

An example of the COSE_Encrypt structure using the HPKE scheme is 
shown in {{hpke-example}}. It uses the following algorithm 
combination: 

- AES-GCM-128 for encryption of the firmware image. 
- AES-GCM-128 for encrytion of the CEK.
- Key Encapsulation Mechanism (KEM): NIST P-256
- Key Derivation Function (KDF): HKDF-SHA256
  
~~~
96( 
    [
        // protected field with alg=AES-GCM-128
        h'A10101',   
        {    // unprotected field with iv
             5: h'26682306D4FB28CA01B43B80'
        }, 
        // null because of detached ciphertext
        null,  
        [  // COSE_recipient_outer
            h'',          // empty protected field
            {             // unprotected field with ... 
                 1: 1     //     alg=A128GCM
            },
            // Encrypted CEK
            h'FA55A50CF110908DA6443149F2C2062011A7D8333A72721A',
            [    // COSE_recipient_inner
                 // protected field with alg HPKE/P-256+HKDF-256 (new)
                 h'A1013818',
                 {  // unprotected field with ...
                    //    HPKE encapsulated key
                    -1: h'A4010220012158205F...979D51687187510C445’,
                    //    kid for recipient static ECDH public key
                     4: h'6B69642D31'
                 }, 
                 // empty ciphertext
                 null
            ]
        ]
     ]
)
~~~
{: #hpke-example title="COSE_Encrypt Example for HPKE"}

# Complete Examples 

TBD: Example for complete manifest here (which also includes the digital signature).
TBD: Multiple recipient example as well. 
TBD: Encryption of manifest (in addition of firmware encryption).

# Security Considerations {#sec-cons}

The algorithms described in this document assume that the firmware author 

- has either shared a key-encryption key (KEK) with the firmware consumer (for use with the AES-Key Wrap scheme), or 
- is in possession of the public key of the firmware consumer (for use with HPKE).  

Both cases require some upfront communication interaction, which is not part of the SUIT manifest. 
This interaction is likely provided by a IoT device management solution, as described in {{RFC9019}}.

For AES-Key Wrap to provide high security it is important that the KEK is of high entropy, and that implementations protect the KEK from disclosure. Compromise of the KEK may result in the disclosure of all key data protected with that KEK.

Since the CEK is randomly generated, it must be ensured that the guidelines for random number generations are followed, see {{RFC8937}}.

#  IANA Considerations

This document requests IANA to create new entries in the COSE Algorithms
registry established with {{I-D.ietf-cose-rfc8152bis-algs}}.

~~~
+-------------+-------+---------+------------+--------+---------------+  
| Name        | Value | KDF     | Ephemeral- | Key    | Description   |
|             |       |         | Static     | Wrap   |               |
+-------------+-------+---------+------------+--------+---------------+
| HPKE/P-256+ | TBD1  | HKDF -  | yes        | none   | HPKE with     |
| HKDF-256    |       | SHA-256 |            |        | ECDH-ES       |
|             |       |         |            |        | (P-256) +     |
|             |       |         |            |        | HKDF-256      |
+-------------+-------+---------+------------+--------+---------------+
| HPKE/P-384+ | TBD2  | HKDF -  | yes        | none   | HPKE with     |
| HKDF-SHA384 |       | SHA-384 |            |        | ECDH-ES       |
|             |       |         |            |        | (P-384) +     |
|             |       |         |            |        | HKDF-384      |
+-------------+-------+---------+------------+--------+---------------+
| HPKE/P-521+ | TBD3  | HKDF -  | yes        | none   | HPKE with     |
| HKDF-SHA521 |       | SHA-521 |            |        | ECDH-ES       |
|             |       |         |            |        | (P-521) +     |
|             |       |         |            |        | HKDF-521      |
+-------------+-------+---------+------------+--------+---------------+
| HPKE        | TBD4  | HKDF -  | yes        | none   | HPKE with     |
| X25519 +    |       | SHA-256 |            |        | ECDH-ES       |
| HKDF-SHA256 |       |         |            |        | (X25519) +    |
|             |       |         |            |        | HKDF-256      |
+-------------+-------+---------+------------+--------+---------------+
| HPKE        | TBD4  | HKDF -  | yes        | none   | HPKE with     |
| X448 +      |       | SHA-512 |            |        | ECDH-ES       |
| HKDF-SHA512 |       |         |            |        | (X448) +      |
|             |       |         |            |        | HKDF-512      |
+-------------+-------+---------+------------+--------+---------------+
~~~ 


--- back



# Acknowledgements

We would like to thank Henk Birkholz for his feedback on the CDDL description in this document. Additionally, we would like to thank Michael Richardson and Carsten Bormann for their review feedback. 

 

