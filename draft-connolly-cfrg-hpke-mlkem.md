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
  FIPS203-ipd:
    title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2023-08-24
    seriesinfo:
      NIST: Federal Information Processing Standards
    format:
      PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf

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

  NIST-PQ:
    title: "Post-Quantum Cryptography"
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2016-2024
    seriesinfo:
      https://csrc.nist.gov/projects/post-quantum-cryptography

  KYBERV302:
    target: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
    title: CRYSTALS-Kyber, Algorithm Specification And Supporting Documentation (version 3.02)
    author:
      -
        ins: R. Avanzi
      -
        ins: J. Bos
      -
        ins: L. Ducas
      -
        ins: E. Kiltz
      -
        ins: T. Lepoint
      -
        ins: V. Lyubashevsky
      -
        ins: J. Schanck
      -
        ins: P. Schwabe
      -
        ins: G. Seiler
      -
        ins: D. Stehle # TODO unicode in references
    date: 2021
    format:
      PDF: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf


--- abstract

This memo defines the ML-KEM-768-based and ML-KEM-1024-based
ciphersuites for HPKE (RFC9180). ML-KEM is believed to be secure even
against adversaries who possess a quantum computer.

--- middle

# Introduction

## Motivation

The final draft for ML-KEM is expected in 2024. For parties that must
move to exclusively post-quantum algorithms, having a pure PQ choice for
public-key hybrid encryption is desireable. HPKE is the leading modern
protocol for public-key encryption, and ML-KEM as a post-quantum
IND-CCA2-secure KEM fits nicely into HPKE's design. Supporting multiple
security levels for ML-KEM allow a spectrum of use cases including
settings where NIST PQ security category 5 is required.

## Not an authenticated KEM {#S-notauth}

ML-KEM is a plain KEM that does not support the static-ephemeral key
exchange that allows HPKE based on Diffie-Hellman based KEMs its
(optional) authenticated modes.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Construction

We construct 'wrapper' KEMs based on ML-KEM to bind the encapsulated
shared secret ciphertext into the shared secret value, such that the
final KEM has similar binding security properties as the original DHKEM
HPKE was designed around.

The encapsulation and decapsulation keys are computed, serialized, and
deserialized the same as in {{FIPS203}}.

We use HKDF-SHA256 and HKDF-SHA512 as the HPKE KDFs and AES-128-GCM and
AES-256-GCM as the AEADs for ML-KEM-768 and ML-KEM-1024 respectively.

## Encap and Decap

~~
def Encap(pkR):
  ss, ct = MLKEM.Encaps(pkR)

  shared_secret = ExtractAndExpand(ss, ct)

  return shared_secret, ct
~~

~~
def Decap(enc, skR):
  ss, ct = MLKEM.Decaps(enc, skR)

  shared_secret = ExtractAndExpand(ss, ct)

  return shared_secret, ct
~~

## AuthEncap and AuthDecap

HPKE-ML-KEM is not an authenticeted KEM and does not support AuthEncap()
or AuthDecap(), see {{S-notauth}}.

# Security Considerations

HPKE's IND-CCA2 security relies upon the IND-CCA2 security of the
underlying KEM and AEAD schemes. ML-KEM is believed to be IND-CCA secure
via multiple analyses.

The HPKE key schedule is independent of the encapsulated KEM shared
secret ciphertext of the ciphersuite KEM, and dependent on the shared
secret produced by the KEM. If HPKE had committed to the encapsulated
shared secret ciphertext, we wouldn't have to worry about the binding
properties of the ciphersuite KEM's X-BIND-K-CT properties. These
computational binding properties for KEMs were formalized in {{CDM23}}.

ML-KEM, unlike DHKEM, is also an implicitly-rejecting instantiation of
the Fujisaki-Okamoto transform, meaning the ML-KEM output shared secret
may be computed differently in case of decryption failure, that reults
in different binding properties, such as the lack of X-BIND-CT-PK and
X-BIND-CT-K completely.

The DHKEM construction in HPKE provides MAL-BIND-K-PK and MAL-BIND-K-CT
security (the shared secret 'binds' or uniquely determines the
encapsulation key and the encapsualted shared secret ciphertext), where
the adversary is able to create the key pairs any way they like in
addition to the key generation. ML-KEM as specified provides
LEAK-BIND-PK,K-CT security, where the involved key pairs are output by
the key generation algorithm of the KEM and then leaked to the
adversary. LEAK-BIND-PK,K-CT is a weaker property than the DHKEM
properties as it is not resistant in the presence of an actively
malicious adversary, and requires both the shared secret _and_the public
key together to uniquely bind the ciphertext, so its shared secret alone
is insufficient.

This results in a wrapper construction around ML-KEM to bind to the
encapsulated shared secret ciphertext as the `kem_context` provided to
`ExtractAndExpand()`. This binds the final `shared_secret` (K) to the
encapsulated shared secret ciphertext (CT), achieving
MAL-BIND-K-CT. ML-KEM already is MAL-BIND-K-PK as the hash of the
encapsulation key (PK) is an input the computation of the shared secret
(K). Together this wrapper KEM matches the binding properties of HPKE's
default KEM construction DHKEM in being MAL-BIND-K-CT and MAL-BIND-K-PK.

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
{:numbered="false"}

The authors would like to thank Cas Cremers for their input.

# Change log

> **RFC Editor's Note:** Please remove this section prior to publication
> of a final version of this document.


## Since draft-connolly-cfrg-hpke-mlkem-00

# Test Vectors

This section contains test vectors formatted similary to that which are
found in {{RFC9180}}, with two changes.  First, we only provide vectors
for the non-authenticated modes of operation.  Secondly, as ML-KEM
encapsulation does not involve an ephemeral keypair, we omit the ikmE,
skEm, pkEm entries and provide an ier entry instead.  The value of ier
is the randomness used to encapsulate, so ier[0:32] is the seed that is
fed to H in the first step of ML-KEM encapsulation in {{FIPS203}}.

## ML-KEM-768, HKDF-SHA256, AES-128-GCM

TODO

## ML-KEM-1024, HKDF-SHA512, AES-256-GCM

TODO
