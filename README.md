# Public Key Secure Transport Layer

[![codecov](https://codecov.io/gh/librelois/pkstl/branch/master/graph/badge.svg)](https://codecov.io/gh/librelois/pkstl)


* [FAQ](#faq)
  * [What is PKSTL ?](#what-is-pkstl)
  * [Why ?](#why)
  * [How it works ?](#how-it-works)
* [Conventions](#conventions)
  * [Endianness](#endianness)
  * [Types definition](#types-definition)
* [Negotiation stage](#negotiation-stage)
* [Messages format](#messages-format)
  * [CONNECT message](#connect-message)
  * [ACK message](#ack-message)
  * [USER message](#user-message)

## FAQ

### What is PKSTL

PKSTL (Public Key Secure Transport Layer) is a security layer that ensures the authenticity and confidentiality of communication between 2 programs over any network (Internet or local network or other).  
PKSTL is agnostic to the underlying network protocol, as long as it allows the exchange of binary messages.  
For example, PKSTL works with the websocket protocol but has no dependence on it.

### Prerequisites

Each of the 2 programs must have an Ed25519 key-pair. The program that initiates the connection (the client in the case of client/server communication) must first know the ed25519 public key of the server that the user wishes to contact.

### Why

The most common secure communication protocols require the generation of certificates signed by a certification authority.

It does not really work in a decentralized way, because you have to be accredited by a "certification authority". However, who decides who can be a certification authority?

In addition, the generation of certificates is either costly or requires complex and regular technical manipulations on the part of the end user of a blockchain server.

In the Duniter/G1 ecosystem, all blockchain servers have their own Ed25519 key-pair. We can use this as a basis so that we do not need certificates and therefore allow end users to have a secure server automatically (zero conf).

### How it works

The communication is symmetrically encrypted via a shared secret generated by Diffie–Hellman exchange.

The first 2 messages exchanged by the 2 programs are in clear but signed, they constitute the negotiation stage. This negotiation stage is used to generate the shared secret and verify that the other program owns the private key corresponding to its public key.

Once this negotiation stage is finalized, all exchanged messages are hashed and encrypted (the signature is no longer necessary at this stage because the hash of the message is also encrypted, so it cannot be altered undetectably by a middle man).

## Conventions

### Endianness

All numbers (integers and floats) are encoded in big endian.

### Types definition

u8 : Unsigned 8-bit integer.  
u16 : Unsigned 16-bit integer.  
u32 : Unsigned 32-bit integer.
u64 : Unsigned 64-bit integer.

## Negotiation stage

The negotiation stage is perfectly symmetrical, so that an observer cannot distinguish the "client" from the "server".
This allows PKSTL to be used in both peer-to-peer and client/server contexts.

Each program sends a CONNECT message and an ACK message. The ACK message is a response to the CONNECT message of the other program.
The progress of the negotiation stage can be described by 2 threads each having 3 steps.

Local thread:

1. Preparation of the CONNECT message
2. CONNECT message sent
3. A valid ACK message has been received

Remote thread:

1. Waiting for the CONNECT message from the other program
2. Receiving a valid CONNECT message
3. A valid ACK message has been sent

When the two threads reach step 3, then the negotiation stage is considered successfully completed.

### Shared secret

The shared secret is generated by Diffie-helman exchange. For security reasons, the key_pair used by each program for the DH exchange is an ephemeral key-pair, randomly generated for one-time use.

The seed for the encryption algorithm is obtained by derivation HMAC_SHA384, the salt of the HMAC function is the largest of the two ephemeral public keys.

### Encryption algorithm

The symmetric encryption algorithm is Chacha20/Poly1305.  
The encryption key corresponds to the first 32 bytes of the seed.
The nonce corresponds to the next 12 bytes, and the `aad` to the last 4 bytes.

## Messages format

All messages are formatted as follows:

| Field              | Size    | Type    | Value      |
|:------------------:|:-------:|:-------:|:----------:|
| MAGIC_VALUE        |    4    |    -    | 0xE2C2E2D2 |
| VERSION            |    4    |     u32 |          1 |
| ENCAPSULED_MSG_LEN |    8    |     u64 |            |
| MSG_TYPE           |    2    |     u16 |    {0,1,2} |
| MSG_CONTENT        |   *X    |  [u8;X] |            |
| SIGNATURE          | 0 or 64 | [u8;64] |            |
| HASH               | 0 or 32 | [u8;32] |            |

*`X = ENCAPSULED_MSG_LEN - 2`

MAGIC_VALUE := Special value to recognize that this is a message of the PKSTL protocol.

VERSION := This field allows the versioning of the PKSTL protocol and therefore future evolution.

ENCAPSULED_MSG_LEN := encapsuled message length (MSG_TYPE + MSG_CONTENT)

MSG_TYPE:

Value | Message type
:-:|:-:
 0 | USER
 1 | CONNECT
 2 | ACK

If `MSG_TYPE == 2`, them all message is encrypted. Else, all message is in clear.

MSG_CONTENT := see details by message type

SIGNATURE := Only provided for CONNECT and ACK messages. Ed25519 signature of all previous bytes.

HASH := Only provided for USER messages. Sha256 hash of all previous bytes.

### CONNECT Message

MSG_CONTENT:

| Field              | Size | Type    | Value      |
|:------------------:|:----:|:-------:|:----------:|
| EPK                |   32 | [u8;32] |            |
| SIG_ALGO           |    4 |     u32 |          1 |
| SIG_PUBKEY         |   32 | [u8;32] |            |
| CUSTOM_DATAS       |   *Y |  [u8;Y] |            |

*`Y = X - 68`

APK := Ephemeral public key.

SIG_ALGO := `1` refers to `Ed25519` algorithm. This field is present to anticipate the use of different algorithms in the future.

SIG_PUBKEY := Signature public key of remote program.

CUSTOM_DATAS := optional free user application datas (in clear).

### ACK Message

MSG_CONTENT:

| Field              | Size | Type    | Value                |
|:------------------:|:----:|:-------:|:--------------------:|
| CHALLENGE          |   32 | [u8;32] | Sha256 of remote EPK |
| CUSTOM_DATAS       |   *Z |  [u8;Z] |                      |

*`Z = X - 32`

CHALLENGE := Sha256 hash of remote ephemeral public key.

CUSTOM_DATAS := optional free user application datas (in clear).

### USER Message

| Field              | Size | Type    | Value                |
|:------------------:|:----:|:-------:|:--------------------:|
| CUSTOM_DATAS       |   *X |  [u8;X] |                      |

CUSTOM_DATAS := user application datas (encrypted).
