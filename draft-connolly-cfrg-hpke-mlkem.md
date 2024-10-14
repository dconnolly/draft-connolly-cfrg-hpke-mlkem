---
title: "ML-KEM for HPKE"
abbrev: hpke-mlkem
category: info

docname: draft-connolly-cfrg-hpke-mlkem-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - post quantum
 - kem
 - PQ
 - hpke
 - hybrid encryption
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "dconnolly/draft-connolly-cfrg-hpke-mlkem"
  latest: "https://dconnolly.github.io/draft-connolly-cfrg-hpke-mlkem/draft-connolly-cfrg-hpke-mlkem.html"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  RFC9180:
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security
  KEMMY24:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg

--- abstract

This document defines Module-Lattice-Based Key-Encapsulation Mechanism
(ML-KEM) as defined in {{FIPS203}} KEM options for Hybrid Public-Key Encryption (HPKE). ML-KEM is
believed to be secure even against adversaries who possess a
cryptographically-relevant quantum computer.

--- middle

# Introduction {#intro}

## Motivation {#motivation}

ML-KEM {{FIPS203}} is a Key-Encapsulation Mechanism (KEM) which is believed
to be secure against both classical and quantum cryptographic attacks. For
parties that must move to exclusively post-quantum algorithms, this document
defines pure post-quantum algorithms for the Hybrid Public-Key Encryption
(HPKE) protocol {{RFC9180}}. ML-KEM as a post-quantum IND-CCA2-secure KEM
fits nicely into HPKE's design. Supporting multiple security levels for
ML-KEM allows a spectrum of use cases including settings where the (United
States) National Institute of Standards (NIST) security category 5 is
required.

## Not an authenticated KEM {#S-notauth}

ML-KEM is a plain KEM that does not support the static-static key exchange
that allows HPKE based on Diffie-Hellman (DH) based KEMs and their (optional)
authenticated modes.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

`GenerateKeyPair`, `DeriveKeyPair`, `SerializePublicKey`,
`DeserializePublicKey`, `Encap`, `Decap`, `AuthEncap`, `AuthDecap`,
`Nsecret`, `Nenc`, `Npk`, and `Nsk` are defined in Section 4 of {{RFC9180}}.

When used in the Security Consideration section, `PK` refers to public key
and `CT` refers to cipher text.

**TODO**: explain or reference IND-CCA, IND-CCA2, MAL-BIND-K-PK,
MAL-BIND-K-CT, and LEAK-BIND-K-PK.

# Usage {#usage}

{{FIPS203}} supports two different key formats. This document only
supports the 64-byte seed `(d, z)`. This format supports stronger binding
properties for ML-KEM than the expanded format. The 64-byte seed format
protects against re-encapsulation attacks. This format provides properties
closer to the generic DHKEM binding properties defined in Section 4.1 of
{{RFC9180}}.

The encapsulation and decapsulation keys are computed, serialized, and
deserialized as described in {{FIPS203}} where the decapsulation keys MUST
be in the 64-byte `(d, z)` format. The 'expanded' format where the
decapsulation key is expanded into a variable size based on the parameter
set but includes the hash of the encapsulation key is not used.

Unlike DHKEM, ML-KEM does not rely on an external Key-Derivation Function
(KDF).

**TODO**: Describe the mapping between `GenerateKeyPair`, `DeriveKeyPair`,
`SerializePublicKey`, `DeserializePublicKey`, `Encap`, and `Decap` in HPKE
and the functions defined in {{FIPS203}}.

## AuthEncap and AuthDecap {#S-auth}

HPKE-ML-KEM is not an authenticated KEM and does not support AuthEncap() or
AuthDecap(), see {{S-notauth}}.

# Security Considerations {#security-considerations}

HPKE's IND-CCA2 security relies upon the IND-CCA and IND-CCA2 security of the
underlying KEM and AEAD schemes, respectively. ML-KEM is believed to be
IND-CCA secure via multiple analyses.

The HPKE key schedule is independent of the encapsulated KEM shared secret
ciphertext and public key of the ciphersuite KEM, and dependent on the shared
secret produced by the KEM. If HPKE had committed to the encapsulated shared
secret ciphertext and public key, we wouldn't have to worry about the binding
properties of the ciphersuite KEM's X-BIND-K-CT and X-BIND-K-PK
properties. These computational binding properties for KEMs were formalized
in {{CDM23}}. {{CDM23}} describes DHKEM as MAL-BIND-K-PK and MAL-BIND-K-CT
secure as a result of the inclusion of the serialized DH public keys (the KEM's
PK and CT) in the DHKEM Key Derivation Function (KDF). MAL-BIND-K-PK and
MAL-BIND-K-CT security ensures that the shared secret 'binds' or uniquely
determines the encapsulation key and the encapsulated shared secret
ciphertext, even when the adversary is able to create or modify the key
pairs or has access to honestly-generated leaked key material.

ML-KEM as specified in {{FIPS203}} with the seed key format provides
MAL-BIND-K-CT security and LEAK-BIND-K-PK security {{KEMMY24}}.
LEAK-BIND-K-PK security is resiliant where the involved key
pairs are output by the honest key generation algorithm of the KEM and then
leaked to the adversary. MAL-BIND-K-CT security strongly binds the shared
secret and the ciphertext even when an adversary can manipulate key material
like the decapsulation key.

ML-KEM using the seed key format (providing MAL-BIND-K-CT and
LEAK-BIND-K-PK) nearly matches the binding properties of DHKEM (the
default HPKE KEM construction). The ML-KEM ciphertext is strongly bound by
the shared secret. The encapsulation key is more weakly bound, and protocols
integrating HPKE using ML-KEM even with the seed key format should evaluate
whether they need to strongly bind to the PK elsewhere (outside of ML-KEM or HPKE) to be
resilient against a MAL adversary, or to achieve other tight binding to the
encapsulation key PK to achieve properties like implicit authentication or
session independence.

# IANA Considerations {#iana}

This document requests/registers two new entries to the "HPKE KEM
Identifiers" registry.

 Value:
 : 0x0040 (please)

 KEM:
 : ML-KEM-512

 Nsecret:
 : 32

 Nenc:
 : 768

 Npk:
 : 800

 Nsk:
 : 1632

 Auth:
 : no

 Reference:
 : This document


 Value:
 : 0x0041 (please)

 KEM:
 : ML-KEM-768

 Nsecret:
 : 32

 Nenc:
 : 1088

 Npk:
 : 1184

 Nsk:
 : 2400

 Auth:
 : no

 Reference:
 : This document


 Value:
 : 0x0042 (please)

 KEM:
 : ML-KEM-1024

 Nsecret:
 : 32

 Nenc:
 : 1568

 Npk:
 : 1568

 Nsk:
 : 3168

 Auth:
 : no

 Reference:
 : This document


--- back

# Acknowledgments

The authors would like to thank Cas Cremers for their input.

# Change log

> **RFC Editor's Note:** Please remove this section prior to publication
> of a final version of this document.

TODO

## Since draft-connolly-cfrg-hpke-mlkem-00

TODO

# Test Vectors

This section contains test vectors formatted similary to that which are found
in {{RFC9180}}, with two changes.  First, we only provide vectors for the
non-authenticated modes of operation.  Secondly, as ML-KEM encapsulation does
not involve an ephemeral keypair, we omit the ikmE, skEm, pkEm entries and
provide an ier entry instead.  The value of ier is the randomness used to
encapsulate, so `ier[0:32]` is the seed that is fed to H in the first step of
ML-KEM encapsulation in {{FIPS203}}.

## ML-KEM-512

TODO

## ML-KEM-768

TODO

## ML-KEM-1024

TODO
