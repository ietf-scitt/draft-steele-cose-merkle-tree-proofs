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
  RFC9162:
  RFC6234:
  RFC8032:
  RFC6979:

informative:
  I-D.ietf-cose-countersign:
  I-D.ietf-scitt-architecture:
  CCF_Merkle_Tree:
    target: https://microsoft.github.io/CCF/main/architecture/merkle_tree.html
    title: CCF - Merkle Tree
    author:
      ins: Microsoft Research

--- abstract

This specification describes three CBOR data structures for primary use in COSE envelopes. A format for Merkle Tree Root Signatures with metadata, a format for Inclusions Paths, and a format for disclosure of a single hadh tree leaf payload (Merkle Tree Proofs).

--- middle

# Introduction

This specification describes three CBOR data structures for primary use in COSE envelopes. A format for Merkle Tree Root Signatures with metadata, a format for Inclusions Paths, and a format for disclosure of a single hadh tree leaf payload (Merkle Tree Proofs).

## Requirements Notation

{::boilerplate bcp14-tagged}

# Terminology

Leaf Bytes:

: TBD

Merkle Tree:

: A Merkle tree is a tree where every leaf is labelled with the cryptographic hash of a sequence of bytes and every node that is not a leaf is labeled with the cryptographic hash of the labels of its child nodes.

Merkle Tree Root:

: A Merkle tree root is the root node of a tree which represents the cryptographic hash that commits to all leaves in the tree.

Merkle Tree Algorithm:

: A Merkle tree algorithm specifies how nodes in the tree must be hashed to compute the root node.

Payload and Extra Data:

: A payload is data bound to in a Merkle tree leaf. The Merkle tree algorithm determines how a payload together with extra data is bound to a leaf. The simplest case is that the payload is the leaf itself without extra data.

Inclusion Path:

: An inclusion path confirms that a value is a leaf of a Merkle tree known only by its root hash (and tree size, possibly).

Signed Merkle Tree Proof:

: A signed Merkle tree proof is the combination of signed Merkle tree root hash, inclusion path, extra data, and payload.

# Merkle Tree Related CBOR Structures

[FIXME] SecIntro Text

## Signed Merkle Tree Root

A Merkle tree root is signed with COSE_Sign1, creating a Signed Merkle Tree Root:

~~~~ cddl
SMTR = THIS.COSE.profile .and COSE_Sign1_Tagged
~~~~

Protected header parameters:

* alg (label: 1): REQUIRED. Signature algorithm. Value type: int / tstr.
* tree alg (label: TBD): REQUIRED. Merkle tree algorithm. Value type: int / tstr.
* tree size (label: TBD): OPTIONAL. Merkle tree size as the number of leaves. Value type: uint.

A COSE profile of this specification may add further header parameters, for example to identify the signer.

Payload: Merkle tree root hash bytes according to tree alg (i.e., header params tell you what the alg id is here)

Note: The payload is just a byte string representing the Merkle tree root hash (and not some wrapper structure) so that it can be detached (see defintion of payload in https://www.rfc-editor.org/rfc/rfc9052#section-4.1) and easily re-computed from an inclusion path and leaf bytes. This allows to design other structures that force re-computation and prevent faulty implementations (forgetting to match a computed root with one embedded in a signature).

## Inclusion Path

If the tree size and leaf index is known, then a compact inclusion path (see, REF NEEDED, CT RFC?) variant can be used:

~~~~ cddl
IndexAwareInclusionPath = #6.1234([
    leaf_index: int
    hashes: [+ bstr]
])
~~~~

Otherwise, the direction for each path step must be included:

FIXME bit vector: 0 right, 1 left, so no bit labels

~~~~ cddl
IndexUnawareInclusionPath = #6.1235([
    hashes: [+ bstr]
    left: uint  ; bit vector
])
~~~~

For some tree algorithms, like Quantum Ledger Data Base (QLDB), the direction is derived from the hashes themselves and both the index and direction can be left out in the path:

~~~~ cddl
; TODO: find a better name for this
UndirectionalInclusionPath = #6.1236([+ bstr])
~~~~

~~~~ cddl
InclusionPath = IndexAwareInclusionPath / IndexUnawareInclusionPath / UndirectionalInclusionPath
~~~~

Note: Including the tree size and leaf index may not be appropriate in certain privacy-focused applications as an attacker may be able to derive private information from them.

TODO: Should leaf index be part of inclusion path (IndexAwareInclusionPath) or outside?

TODO: Define root computation algorithm for each inclusion path type

TODO: [Do we need both inclusion path types? what properties does each type have?](https://github.com/ietf-scitt/cose-merkle-tree-proofs/issues/6)

TODO: Should the inclusion path be opaque (bstr) and fixed by the tree algorithm? It seems this is orthogonal and the choice of inclusion path type should be application-specific.

## Signed Merkle Tree Proof

A signed Merkle tree proof is a CBOR array containing a signed tree root, an inclusion path, extra data for the tree algorithm, and the payload.

~~~~ cddl
SignedMerkleTreeProof = [
  signed_tree_root: bstr .cbor SMTR  ; payload of COSE_Sign1_Tagged is detached
  inclusion_path: bstr .cbor InclusionPath
  extra_data: bstr / nil
  payload: bstr
]
~~~~

`extra_data` is an additional input to the tree algorithm and is used together with the payload to compute the leaf hash. A use case for this field is to implement blinding.

TODO: maybe rename `extra_data`

## Signed Merkle Tree Multiproof

TODO: define a multi-leaf variant of a signed Merkle tree proof like in:

* https://github.com/transmute-industries/merkle-proof
* https://transmute-industries.github.io/merkle-disclosure-proof-2021/

TODO: consider using sparse multiproofs, see https://medium.com/@jgm.orinoco/understanding-sparse-merkle-multiproofs-9b9f049e8f08 and https://arxiv.org/pdf/2002.07648.pdf

# Merkle Tree Algorithms

This document establishes a registry of Merkle tree algorithms with the following initial contents:

[FIXME] exploration table, what should go into -00?

| Name              | Label | Description
|---
|Reserved           | 0     |
|RFC9162_SHA256     | 1     | RFC9162 with SHA-256
|QLDB_SHA256        | 3     | QLDB with SHA-256
{: align="left" title="Merke Tree Alogrithms"}

Each tree algorithm defines how to compute the root node from a sequence of leaves each represented by payload and extra data. Extra data is algorithm-specific and should be considered opaque.

## RFC9162_SHA256

The `RFC9162_SHA256` tree algorithm uses the Merkle tree definition from {{RFC9162}} with SHA-256 hash algorithm.

For n > 1 inputs, let k be the largest power of two smaller than n.

~~~~
MTH({d(0)}) = SHA-256(0x00 || d(0))
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
~~~~

where `d(0)` is the payload. This algorithm takes no extra data.

## QLDB_SHA256

The `QLDB_SHA256` tree algorithm uses the Merkle tree definition from TBD with SHA-256 hash algorithm.

For n > 1 inputs, let k be the largest power of two smaller than n.

~~~~
MTH({d(0)}) = SHA-256(d(0))
MTH(D[n]) = SHA-256(DOT(MTH(D[0:k]), MTH(D[k:n])))
DOT(H1, H2) = if H1 < H2 then H1 || H2 else H2 || H1
~~~~

where `d(0)` is the payload. This algorithm takes no extra data.

# Privacy Considerations

TBD

# Security Considerations

TBD

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Header Parameters Registry

IANA will be requested to register the new COSE Header parameters defined below in the "COSE Header Parameters" registry at some point

## New SCITT-Related Registries

IANA will be asked to add a new registry "TBD" to the list that appears at https://www.iana.org/assignments/.

The rest of this section defines the subregistries that are to be created within the new "TBD" registry.

### Tree Algorithms {#tree-alg-registry}

IANA will be asked to establish a registry of tree algorithm identifiers, named "Tree Algorithms", with the following registration procedures: TBD

The "Tree Algorithms" registry initially consists of:

| Identifier | Tree Algorithm       | Reference     |
| CCF        | CCF tree algorithm   | This document |
{: title="Initial content of Tree Algorithms registry"}

The designated expert(s) should ensure that the proposed algorithm has a public specification and is suitable for use as [TBD].

### Signature Algorithms {#sig-alg-registry}

IANA might be asked to establish a registry of signature algorithm identifiers, named "Signature Algorithms", with the following registration procedures: TBD

The "Signature Algorithms" registry initially consists of:

| Identifier | Signature Algorithm | Reference |
| ES256      | Deterministic ECDSA (NIST P-256) with HMAC-SHA256 | {{RFC6979}} |
{: title="Initial content of Signature Algorithms registry"}

The designated expert(s) should ensure that the proposed algorithm has a public specification and is suitable for use as a cryptographic signature algorithm.

--- back

