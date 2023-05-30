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
  RFC8152: cose
  RFC6234:
  RFC8032:
  RFC6979:
  RFC8126: iana-considerations-guide

informative:
  I-D.ietf-cose-countersign:
  I-D.ietf-scitt-architecture: scitt-architecture

--- abstract

This specification describes three CBOR data structures for primary use in COSE envelopes.
A CBOR encoding of Merkle Roots for use in COSE payloads.
A CBOR encoding of Inclusions Proofs for use in COSE unprotected headers.
A CBOR encoding of Consistency Proofs for use in COSE unprotected headers.

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

: An inclusion path enables a verifier to recompute a root, given a leaf and extra data.

Inclusion Proof:

: An inclusion proof is a combination of the extra data, inclusion path and a merkle tree root.

Signed Inclusion Proof:

: A signed inclusion proof is a combination of the inclusion path and signed envelope that includes a merkle root.

# CBOR Merkle Structures

This section describes representations of merkle proof structures in CBOR.

Some of the structures such as the construction of a merkle tree leaf,
or an inclusion proof from a leaf to a merkle root, might have several different representations.

Some differences in representations are necessary to support efficient
verification of different kinds of inclusion proofs and for compatibility with deployed tree algorithms used in specific implementations.

In case of {{-certificate-transparency-v2}}, this is defined in Section 2.1.1. Definition of the Merkle Tree.

## Inclusion Proof

{{-certificate-transparency-v1}} defines a merkle audit path for a leaf in a merkle tree
as the shortest list of additional nodes in the merkle tree required to compute the merkle root for that tree.

{{-certificate-transparency-v2}} changed the term from "merkle audit path" to "merkle inclusion proof".

We prefer to use the term "inclusion path" to avoid confusion with Signed Inclusion Proof.

For tree algorithm "RFC9162_SHA256", we define the following compact encoding of an inclusion proof for a leaf:

~~~~ cddl
inclusion-proof = #6.1234([
    tree-size: int
    leaf-index: int
    inclusion-path: [+ bstr]
])
~~~~

Leaf index is also sometimes referred to as sequence number.

## Signed Inclusion Proof

A Merkle root is signed with COSE_Sign1:

~~~~ cddl
smtr = THIS.COSE.profile .and COSE_Sign1_Tagged
~~~~

Protected header parameters:

* alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int / tstr.
* tree_alg (label: TBD): REQUIRED. Merkle tree algorithm identifier. Value type: int / tstr.
* crit (label: 2): REQUIRED. Criticality marker. Value type: [ +label ]

The criticality header MUST contain the tree_alg label.

The envelope payload MUST be computed by the process defined for the tree_alg.

The envelope payload MUST be detached, and recomputed by the verifier.

One example of a Signed Inclusion Proof is a "transparent statement" as defined in {{-scitt-architecture}}.

~~~~
# COSE_Sign1
18([

  # Protected Header
  h'a2012604588368747470733a2f2f73636974742e78797a2f75726e3a696574663a706172616d733a7472616e733a696e636c7573696f6e3a726663393136325f7368613235363a303a65343263333764326638306361613464323035353635376534303463386538363838313534346136663264313731356530663564616435643436343833633531',
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "tree_alg" : "RFC9162_SHA256",
  #   TBD_1 : 1,
  # }

  # Unprotected Header
  {
      # "inclusion-proof" : "h'3133312c322c302c3132392c3231362c36342c38382c33322c3235342c3132382c33392c34392c3131382c312c3230352c38372c3235332c3136312c31332c3136312c38352c3139302c3133322c3234312c3137332c34352c3132372c32302c35302c35342c31332c3134342c33332c3233372c3234382c3132382c32332c3138392c3133352c3932'"
      TBD_2 : h'3133312c322c302c3132392c3231362c36342c38382c33322c3235342c3132382c33392c34392c3131382c312c3230352c38372c3235332c3136312c31332c3136312c38352c3139302c3133322c3234312c3137332c34352c3132372c32302c35302c35342c31332c3134342c33332c3233372c3234382c3132382c32332c3138392c3133352c3932'
  },

  # Detached Payload

  # Signature
  h'4862c1dced27ceeb1f7a6277d13be127a8969a7171ae000ffa90ef5757b817ca8ee61d57645d1a087251a97f06eb61aec46ecf958e4a0fb94ae37f410c7f77ea'
])
~~~~

### Array form CDDL

~~~~ cddl
signed-inclusion-proof = [
  signed-inclusion-proof: bstr .cbor smtr ; the payload is a merkle root, as described by the tree algorithm, and is detached.
  inclusion-proof: bstr .cbor inclusion-proof ; the inclusion-proof, as described in the tree algorithm
  leaf: bstr ; the leaf, as described in the tree algorithm
]
~~~~

## Signed Consistency Proof

~~~~
# COSE_Sign1
18([

  # Protected Header
  h'a2012604588568747470733a2f2f73636974742e78797a2f75726e3a696574663a706172616d733a7472616e733a636f6e73697374656e63793a726663393136325f7368613235363a303a66653830323733313736303163643537666461313064613135356265383466316164326437663134333233363064393032316564663838303137626438373563',
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "tree_alg" : "RFC9162_SHA256",
  #   TBD_1 : 1,
  # }

  # Unprotected Header
  {
      # "consistency-proof" : "h'3133312c312c312c3132392c3231362c36342c38382c33322c3235342c3132382c33392c34392c3131382c312c3230352c38372c3235332c3136312c31332c3136312c38352c3139302c3133322c3234312c3137332c34352c3132372c32302c35302c35342c31332c3134342c33332c3233372c3234382c3132382c32332c3138392c3133352c3932'"
      TBD_3 : h'3133312c312c312c3132392c3231362c36342c38382c33322c3235342c3132382c33392c34392c3131382c312c3230352c38372c3235332c3136312c31332c3136312c38352c3139302c3133322c3234312c3137332c34352c3132372c32302c35302c35342c31332c3134342c33332c3233372c3234382c3132382c32332c3138392c3133352c3932'
  },

  # Protected Payload
  h'fe8027317601cd57fda10da155be84f1ad2d7f1432360d9021edf88017bd875c',

  # Signature
  h'fe476fcddb783805fe344fc96837f4a5531c2e5a56d6f6353831e84e17ac69d4407a5a0d6eadf27f3a570bcf604181fd11b4692d3ac17b116c6226ba43726113'
])
~~~~

### Array form CDDL

~~~~ cddl
signed-consistency-proof = [
  signed-consistency-proof: bstr .cbor smtr ; the payload is a merkle root, as described by the tree algorithm, and is *attached*.
  consistency-proof: bstr .cbor consistency-proof ; the consistency-proof, as described in the tree algorithm
]
~~~~

# Merkle Tree Algorithms {#sec-merkle-tree-algorithms}

This document establishes a registry of merkle tree algorithms with the following initial contents:

| Identifier            | Tree Algorithm | Reference
|---
|0 | N/A                |
|1 | RFC9162_SHA256     | {{-certificate-transparency-v2}}
{: #merkle-tree-alg-values align="left" title="Merke Tree Alogrithms"}

Each tree algorithm defines:

0. How to compute a leaf from a payload and extra data, such as the current size of the tree.
1. How to compute the merkle root from a sequence of leaves.
2. How to compute an inclusion-proof for a leaf.
3. How to compute a consistency-proof for a leaf.

Each specification MUST define how to encode each of these parameters in CBOR, and map them to:

- TBD_1 - (tree alg)
- TBD_2 - (inclusion proof)
- TBD_3 - (consistency proof)

See {{sec-rfc-9162-tree-alg-definition}} as an example.

## The RFC9162_SHA256 Tree Algorithm {#sec-rfc-9162-tree-alg-definition}

This section defines how to map the data structures described in {{-certificate-transparency-v2}}
to the terminology defined in this document, using cbor and cose.

### Tree Algorithm

The integer identifier for "tree-alg" is 1.
The string identifier for "tree-alg" is "RFC9162_SHA256".

### Tree Definition

See {{-certificate-transparency-v2}}, 2.1.1. Definition of the Merkle Tree.

#### Merkle Root

The cbor representation of a merkle root is the bytestring represenation of MTH.

#### Inclusion Proof

See {{-certificate-transparency-v2}}, 2.1.3.1. Generating an Inclusion Proof.

The cbor representation of the inclusion proof is:

~~~~ cddl
inclusion-proof = #6.1234([
    tree-size: int
    leaf-index: int
    inclusion-path: [+ bstr]
])
~~~~

#### Consistency Proof

See {{-certificate-transparency-v2}}, 2.1.4.1. Generating a Consistency Proof.

The cbor representation of the consistency proof is:

~~~~ cddl
consistency-proof = #6.1234([
    tree-size-1: int ; size of the tree, when the previous root was produced.
    tree-size-2: int ; size of the tree, when the latest root was produced.
    consistency-path: [+ bstr] ; consistency path, from previous root to latest root.
])
~~~~

Editors note: tree-size-1, could be ommited, if an inclusion-proof is always present, since the inclusion proof contains, tree-size-1.

## Signed Proofs

In a signed inclusion proof, the previous merkle tree root, maps to tree-size-1, and is a detached payload.
In a signed consistency proof, the latest merkle tree root, maps to tree-size-2, and is an attached payload.

# Privacy Considerations

See the privacy considerations section of:

- {{-certificate-transparency-v2}}
- {{-cose}}

## Leaf Blinding {#sec-leaf-blinding}

In cases where a single merkle root and multiple inclusion paths are used to prove inclusion for multiple payloads. There is a risk that an attacker may be able to learn the content of undisclosed payloads, by brute forcing the values adjacent to the disclosed payloads through application of the cryptographic hash function and comparison to the the disclosed inclusion paths. This kind of attack can be mitigated by including a cryptographic nonce in the construction of the leaf, however this nonce must then disclosed along side an inclusion proof which increases the size of multiple payload signed inclusion proofs.

Tree algorithm designers are encouraged to comment on this property of their leaf construction algorithm.


# Security Considerations

See the privacy considerations section of:

- {{-certificate-transparency-v2}}
- {{-cose}}

## Hash Function Agility

The choice of cryptographic hash function is the primary primitive impacting the security of authenticating payload inclusion in a merkle root. Tree algorithm designers should review the latest guidance on selecting a suitable cryptographic hash function.

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Header Parameters Registry

This document requests IANA to add new values to the 'COSE
Algorithms' and to the 'COSE Header Algorithm Parameters' registries
in the 'Standards Action With Expert Review category.

#### COSE Header Algorithm Parameters

* Name: tree_alg
* Label: TBD_1
* Value type: tree_alg
* Value registry: See {{tree-alg-registry}}
* Description: Merkle tree algorithm used to produce a COSE Sign1 payload.

* Name: inclusion_proof
* Label: TBD_2
* Value type: inclusion_proof
* Value registry: See {{tree-alg-registry}}
* Description: Merkle tree inclusion proof for the given tree_alg.

* Name: consistency_proof
* Label: TBD_2
* Value type: consistency_proof
* Value registry: See {{tree-alg-registry}}
* Description: Merkle tree consistency proof for the given tree_alg.


### Tree Algorithms {#tree-alg-registry}

IANA will be asked to establish a registry of tree algorithm identifiers, named "Tree Algorithms" to be administered under a Specification Required policy {{-iana-considerations-guide}}.

Template:

* Identifier: The two-byte identifier for the algorithm
* Tree Algorithm: The name of the algorithm
* Reference: Where this algorithm is defined

Initial contents: Provided in {{merkle-tree-alg-values}}

--- back

### Blinding Example {#sec-leaf-blinding-example}

Implementers wishing to leverage this tree algorithm with multiple inclusion proofs, may prepend payload with extra data before applying the tree algorithm, where extra data is a cryptographic nonce.

