---
v: 3

title: Concise Encoding of Signed Merkle Tree Proofs
abbrev: CoMETRE
docname: draft-steele-cose-merkle-tree-proofs-latest
stand_alone: true
ipr: trust200902
area: Security
wg: TBD
kw: Internet-Draft
cat: std
submissiontype: IETF
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- ins: O. Steele
  name: Orie Steele
  organization: Transmute
  email: orie@transmute.industries
  country: United States
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: M. Riechert
  name: Maik Riechert
  organization: Microsoft
  email: Maik.Riechert@microsoft.com
  country: UK
- ins: A. Delignat-Lavaud
  name: Antoine Delignat-Lavaud
  organization: Microsoft
  email: antdl@microsoft.com
  country: UK
- ins: C. Fournet
  name: Cedric Fournet
  organization: Microsoft
  email: fournet@microsoft.com
  country: UK

normative:
  RFC8949:
  RFC6962: certificate-transparency-v1
  RFC9162: certificate-transparency-v2
  RFC6234:
  RFC8032:
  RFC6979:
  RFC9053: COSE
  RFC8126: iana-considerations-guide
  BCP205: RFC7942

informative:
  I-D.ietf-cose-countersign:
  I-D.ietf-scitt-architecture: scitt-architecture

--- abstract

This specification describes three CBOR data structures for primary use in COSE envelopes. A format for Merkle Tree Root Signatures with metadata, a format for Inclusions Paths, and a format for disclosure of a single hadh tree leaf payload (Merkle Tree Proofs).

--- middle

# Introduction

Merkle trees are verifiable data structures that support secure data storage,
through their ability to protect the integrity of batches of documents or collections of statements.

A merkle proof is a path from a leaf to a root in a merkle tree.

Merkle proofs can be used to prove a document is in a database (proof of inclusion),
or that a smaller set of statements are contained in a large set of statements (selective disclosure proofs).

Typically, merkle trees are constructed from simple operations such as concatenation and digest via a cryptographic hash function.

The simple design and valuable cryptographic properties of merkle trees have been leveraged in many network and database applications.

Differences in the representation of a merkle tree, merkle leaf and merkle inclusion proof can increase the
burden for implementers, and create interoperability challenges.

This document describes the three data structures necessary to use merkle proofs with COSE envelopes.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Terminology

Leaf:

: A merkle tree leaf is the cryptographic hash of a sequence of bytes that combines Leaf Payload and Extra Data.

Merkle Tree:

: A Merkle tree is a tree where every leaf is a cryptographic hash of a sequence of
bytes and every node that is not a leaf is the cryptographic hash of the its child nodes.

Merkle Root:

: A Merkle root is the root node of a tree; this cryptographic hash is a committment to the content of the tree.

Merkle Tree Algorithm:

: A Merkle tree algorithm specifies how to construct the tree and how to compute its root.

Leaf Payload and Extra Data:

: A leaf payload is application data used to produce a Leaf.
The Merkle tree algorithm determines how a payload together with extra data is used to produce a leaf.
The simplest case is that the leaf is the cryptographic hash of the payload without extra data.

Inclusion Path:

: An inclusion path enables a verifier to recompute a root, given a leaf.

Inclusion Proof:

: An inclusion proof is a combination of the leaf payload, extra data, inclusion path and a merkle tree root.

Signed Inclusion Proof:

: A signed inclusion proof is a combination of the leaf payload, extra data, inclusion path and signed envelope that includes a merkle root.

# CBOR Merkle Structures

This section describes representations of merkle proof structures in CBOR.

Some of the structures such as the construction of a merkle tree leaf,
or an inclusion proof from a leaf to a merkle root, might have several different representations.

Some differences in representations are necessary to support efficient
verification of different kinds of inclusion proofs and for compatibility with deployed tree algorithms used in specific implementations.

## Signed Inclusion Proof

A Merkle root is signed with COSE_Sign1:

~~~~ cddl
smtr = THIS.COSE.profile .and COSE_Sign1_Tagged
~~~~

Protected header parameters:

* alg (label: 1): REQUIRED. Signature algorithm. Value type: int / tstr.
* tree alg (label: TBD): REQUIRED. Merkle tree algorithm. Value type: int / tstr.

A COSE profile of this specification may add further header parameters, for example to identify the signer or add a timestamp.

Envelope Payload: A Merkle tree root according to the tree alg.

The envelope payload can be detached, since it can be recomputed by the verifier.

Forcing a verifier to perform re-computation can prevent faulty implementations.

One example of a Signed Inclusion Proof is a "transparent statement" as defined in {{-scitt-architecture}}.

## Inclusion Paths

{{-certificate-transparency-v1}} defines a merkle audit path for a leaf in a merkle tree
as the shortest list of additional nodes in the merkle tree required to compute the merkle root for that tree.

{{-certificate-transparency-v2}} changed the term from "merkle audit path" to "merkle inclusion proof".

We prefer to use the term "inclusion path" to avoid confusion with Signed Inclusion Proof.

Editors note: We may want to move inclusion path representations to the specification that is required to register a new algorithm in the proposed tree algorithms registry.

Editors note: We recommend tree algorithm simple take the inclusion path as opaque bytes.

If the tree size and leaf index is known, then a compact inclusion path variant can be used:

~~~~ cddl
index-aware-inclusion-path = #6.1234([
    tree-size: int
    leaf-index: int
    hashes: [+ bstr]
])
~~~~

Leaf index is also sometimes referred to as sequence number.

Otherwise, the direction each path step must be included:

FIXME bit vector: 0 right, 1 left, so no bit labels

~~~~ cddl
index-unaware-inclusion-path = #6.1235([
    hashes: [+ bstr]
    left: uint  ; bit vector
])
~~~~

For some tree algorithms, the direction is derived from the hashes themselves and both the index and direction can be left out in the path:

~~~~ cddl
sorted-inclusion-proof = #6.1236([+ bstr])
~~~~

~~~~ cddl
inclusion-path = index-aware-inclusion-path / index-unaware-inclusion-path / sorted-inclusion-proof
~~~~

Presence of leaf index, and whether it is an input or an output is tree algorithm specific.

## Inclusion Proof

An inclusion proof is a CBOR array containing a merkle tree root, an inclusion path, extra data for the tree algorithm, and the payload.

~~~~ cddl
inclusion-proof = [
  merkle-tree-root: bstr ;
  inclusion-path: bstr .cbor inclusion-path
  extra-data: bstr / nil
  leaf-payload: bstr ;
]
~~~~

## Signed Inclusion Proof

A signed inclusion proof is a CBOR array containing a signed tree root, an inclusion path, extra data for the tree algorithm, and the payload.

~~~~ cddl
signed-inclusion-proof = [
  signed-tree-root: bstr .cbor smtr ; payload of COSE_Sign1_Tagged is detached
  inclusion-path: bstr .cbor inclusion-path
  extra-data: bstr / nil
  leaf-payload: bstr ; leaf payload, not payload in signed_tree_root, could be detached.
]
~~~~

`extra-data` is an additional input to the tree algorithm and is used together with the payload to compute the leaf hash. See {{sec-leaf-blinding-example}} for an example use case for this field to enable leaf blinding as described in
{{sec-leaf-blinding}}.

## Signed Multiple Inclusion Proofs

### Sorted Hashes Multiproof

This signed mulitple inclusion proof representation relies on 2 lists to enable proof of inclusion for multiple payloads in a given signed merkle root.

Note that the extra-data may be ommited if not required by the tree algorithm, and that leaf payloads may be detached.

~~~~ cddl
signed-multiple-inclusion-proof = [
  signed-tree-root: bstr .cbor smtr ; payload of COSE_Sign1_Tagged is detached
  inclusion-paths: [+ [ bstr / nil .cbor extra-data, bstr .cbor inclusion-path] ]
  leaf-payloads: [+ bstr] ; leaf payloads, could be detached.
]
~~~~

TODO: refine multi-leaf variant of a signed inclusion proof like in:

* https://github.com/transmute-industries/merkle-proof
* https://transmute-industries.github.io/merkle-disclosure-proof-2021/

TODO: consider using sparse multiproofs, see https://medium.com/@jgm.orinoco/understanding-sparse-merkle-multiproofs-9b9f049e8f08 and https://arxiv.org/pdf/2002.07648.pdf

# Merkle Tree Algorithms {#sec-merkle-tree-algorithms}

This document establishes a registry of merkle tree algorithms with the following initial contents:


| Identifier            | Tree Algorithm | Reference
|---
|0 | N/A                |
|1 | RFC9162_SHA256     | {{-certificate-transparency-v2}}
{: #merkle-tree-alg-values align="left" title="Merke Tree Alogrithms"}

Each tree algorithm defines how to compute the root node from a sequence of leaves each represented by payload and extra data. Extra data is algorithm-specific and should be considered opaque.

# Privacy Considerations

TBD

## Leaf Blinding {#sec-leaf-blinding}

In cases where a single merkle root and multiple inclusion paths are used to prove inclusion for multiple payloads. There is a risk that an attacker may be able to learn the content of undisclosed payloads, by brute forcing the values adjacent to the disclosed payloads through application of the cryptographic hash function and comparison to the the disclosed inclusion paths. This kind of attack can be mitigated by including a cryptographic nonce in the construction of the leaf, however this nonce must then disclosed along side an inclusion proof which increases the size of multiple payload signed inclusion proofs.


# Security Considerations

TBD

## Hash Function Agility

The choice of cryptographic hash function is the primary primitive impacting the security of authenticating payload inclusion in a merkle root. Tree algorithm designers should review the latest guidance on selecting a suitable cryptographic hash function.

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Header Parameters Registry

IANA will be requested to register the new COSE Header parameters defined below in the "COSE Header Parameters" registry at some point.

* Name: tree_alg
* Label: TBD
* Value type: tree_alg
* Value registry: See {{tree-alg-registry}}
* Description: Merkle tree algorithm used to produce a COSE Sign1 payload.

## New SCITT-Related Registries

IANA will be asked to add a new registry "TBD" to the list that appears at [IANA Assignments](https://www.iana.org/assignments/).

The rest of this section defines the subregistries that are to be created within the new "TBD" registry.

### Tree Algorithms {#tree-alg-registry}

IANA will be asked to establish a registry of tree algorithm identifiers, named "Tree Algorithms" to be administered under a Specification Required policy {{-iana-considerations-guide}}.

Template:

* Identifier: The two-byte identifier for the algorithm
* Tree Algorithm: The name of the algorithm
* Reference: Where this algorithm is defined

Initial contents: Provided in {{merkle-tree-alg-values}}

--- back

# Example Tree Algorithms

## RFC9162_SHA256

The `RFC9162_SHA256` tree algorithm uses the merkle tree definition from {{-certificate-transparency-v2}} with SHA-256 hash algorithm.

For n > 1 inputs, let k be the largest power of two smaller than n.

~~~~
MTH({d(0)}) = SHA-256(0x00 || d(0))
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
~~~~

where `d(0)` is the payload. By default this algorithm takes no extra data.

### Blinding Example {#sec-leaf-blinding-example}

Implementers wishing to leverage this tree algorithm with multiple inclusion proofs, may prepend payload with extra data before applying the tree algorithm, where extra data is a cryptographic nonce.

# Implementation Status

Note to RFC Editor: Please remove this section as well as references to {{BCP205}} before AUTH48.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{BCP205}}.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to {{BCP205}},
"this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Implementer

An open-source implementation was initiated and is maintained by the Transmute Industries Inc. - Transmute.

## Implementation Name

An application demonstrating the concepts is available at [https://scitt.xyz](https://scitt.xyz).

## Implementation URL

An open-source implementation is available at:

- https://github.com/transmute-industries/cose

## Maturity

The code's level of maturity is considered to be "prototype".

## Coverage and Version Compatibility

The current version ('main') implements the tree algorithm, inclusion proof and consistency proof concepts of this draft.

## License

The project and all corresponding code and data maintained on GitHub are provided under the Apache License, version 2.

## Implementation Dependencies

The implementation builds on concepts described in SCITT {{-scitt-architecture}} (https://scitt.io/).

The implementation uses the Concise Binary Object Representation {{-CBOR}} (https://cbor.io/).

The implementation uses the CBOR Object Signing and Encryption {{-COSE}}, maintained at:
- https://github.com/erdtman/cose-js

The implementation uses an implementation of {{-certificate-transparency-v2}},
maintained at:

- https://github.com/transmute-industries/rfc9162/tree/main/src/CoMETRE

## Contact

Orie Steele (orie@transmute.industries)
