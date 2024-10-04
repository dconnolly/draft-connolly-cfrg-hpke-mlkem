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
  github: "dconnolly/draft-connolly-cfrg-xwing-kem"
  latest: "https://dconnolly.github.io/draft-connolly-cfrg-xwing-kem/draft-connolly-cfrg-xwing-kem.html"

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

This memo defines the ML-KEM-based ciphersuites for HPKE (RFC9180). ML-KEM is believed to be secure
even against adversaries who possess a quantum computer.

--- middle

# Introduction {#intro}

## Motivation {#motiv}

The final draft for ML-KEM is expected in 2024. For parties that must
move to exclusively post-quantum algorithms, having a pure PQ choice for
public-key hybrid encryption is desireable. HPKE is the leading modern
protocol for public-key encryption, and ML-KEM as a post-quantum
IND-CCA2-secure KEM fits nicely into HPKE's design. Supporting multiple
security levels for ML-KEM allows a spectrum of use cases including
settings where NIST PQ security category 5 is required.

## Not an authenticated KEM {#S-notauth}

ML-KEM is a plain KEM that does not support the static-static key
exchange that allows HPKE based on Diffie-Hellman based KEMs its
(optional) authenticated modes.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

# Usage {#usage}

{{FIPS203}} supports two different key formats, but this document only
supports the 64-byte seed `(d, z)`. This format supports stronger binding
properties for ML-KEM than the expanded format that protect against
re-encapsulation attacks and bring the usage of ML-KEM in practice closer to
the generic DHKEM binding properties as defined in {{RFC9180}}.

We construct 'wrapper' KEMs based on ML-KEM to bind the KEM shared secret to
the KEM ciphertext, such that the final KEM has similar binding security
properties as the original DHKEM which HPKE was designed around.

The encapsulation and decapsulation keys are computed, serialized, and
deserialized the same as in {{FIPS203}} where the decapsulation keys MUST be
in the 64-byte `(d, z)` format. The 'expanded' format where the decapsulation
key is expanded into a variable size based on the parameter set but includes
the hash of the encapsulation key MUST NOT be used.

We use HKDF-SHA256 and HKDF-SHA512 as the HPKE KDFs and AES-128-GCM and
AES-256-GCM as the AEADs for ML-KEM-512, ML-KEM-768, and ML-KEM-1024,
respectively.

## AuthEncap and AuthDecap

HPKE-ML-KEM is not an authenticated KEM and does not support AuthEncap()
or AuthDecap(), see {{S-notauth}}.

# Security Considerations

HPKE's IND-CCA2 security relies upon the IND-CCA and IND-CCA2 security
of the underlying KEM and AEAD schemes, respectively. ML-KEM is believed
to be IND-CCA secure via multiple analyses.

The HPKE key schedule is independent of the encapsulated KEM shared secret
ciphertext of the ciphersuite KEM, and dependent on the shared secret
produced by the KEM. If HPKE had committed to the encapsulated shared secret
ciphertext, we wouldn't have to worry about the binding properties of the
ciphersuite KEM's X-BIND-K-CT properties. These computational binding
properties for KEMs were formalized in {{CDM23}}. {{CDM23}} describes DHKEM
as LEAK-BIND-K-PK and LEAK-BIND-K-CT secure as result of the inclusion of the
serialized DH public keys in the DHKEM KDF; however it expects pre-validated
keys and never explicitly rejects, making it implicitly-rejecting KEM.

ML-KEM, unlike DHKEM, is also an implicitly-rejecting instantiation of
the Fujisaki-Okamoto transform, meaning the ML-KEM output shared secret
may be computed differently in case of decryption failure, that reults
in different binding properties, such as the lack of X-BIND-CT-PK and
X-BIND-CT-K completely.

The DHKEM construction in HPKE can provide MAL-BIND-K-PK and MAL-BIND-K-CT
security (the shared secret 'binds' or uniquely determines the encapsulation
key and the encapsualted shared secret ciphertext), where the adversary is
able to create the key pairs any way they like in addition to the key
generation. ML-KEM as specified with the seed key format provides
MAL-BIND-K-CT security and LEAK-BIND-K-PK security
{{KEMMY24}}. LEAK-BIND-K-PK security is resiliant where the involved key
pairs are output by the key generation algorithm of the KEM and then leaked
to the adversary. MAL-BIND-K-CT security strongly binds the shared secret and
the ciphertext even when an adversary can manipulate key material like the
decapsulation key.

ML-KEM nearly matches the binding properties of HPKE's default KEM generic
construction DHKEM in being MAL-BIND-K-CT and LEAK-BIND-K-PK, and in fact
exceeds the bar set by DHKEM in being MAL-BIND-K-CT secure when using the
seed key format.

# IANA Considerations

This document requests/registers two new entries to the "HPKE KEM
Identifiers" registry.

 Value:
 : 0x0070 (please)

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
 : 0x0080 (please)

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

This section contains test vectors formatted similary to that which are
found in {{RFC9180}}, with two changes.  First, we only provide vectors
for the non-authenticated modes of operation.  Secondly, as ML-KEM
encapsulation does not involve an ephemeral keypair, we omit the ikmE,
skEm, pkEm entries and provide an ier entry instead.  The value of ier
is the randomness used to encapsulate, so `ier[0:32]` is the seed that is
fed to H in the first step of ML-KEM encapsulation in {{FIPS203}}.

## ML-KEM-512, HKDF-SHA256, AES-128-GCM

TODO

## ML-KEM-768, HKDF-SHA256, AES-128-GCM

TODO

## ML-KEM-1024, HKDF-SHA512, AES-256-GCM

TODO
