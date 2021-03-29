# js-mutual-auth-ecies
The Diffie-Hellman Integrated Encryption Scheme ([DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf)), or the Elliptic Curve Integrated Encryption Scheme ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)), as it is commonly referred to due to its most prominent instantiation based on elliptic curve-based groups, is a construction of a hybrid encryption scheme that has a wide array of attractive security properties. Examples include, semantic security against CCA and CCP enabled adversaries in the **standard model**. Moreover, ECIES provides several features that are important from a practical perspective, i.e., that are relevant to implementers/developers, such as efficiency, flexibility in terms of the employed cryptographic group, the symmetric encryption scheme, KMAC scheme and hash functions, as well as, an arbitrary message space.

In this repository, a JavaScript implementation of ECIES is provided, however, **with the added property that the message sender authenticates herself to the receiver (and only to the receiver). We stress that this is not the case in the standard ECIES scheme.** Hence, the reason why this repo is entitled `js-mutual-auth-ecies`.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated with the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. To maintain compatibility with the OpenDSU codebase, the implementation provided here depends on the `pskcrypto` module of OpenDSU which, for your convenience dear sir/madam/wherever-in-the-gender-spectrum-you-are, is provided here!

# Overview
This repository provides two implementations of ECIES, namely:

- [ECIESDS](#eciesds): This acronym stands for ECIES with Digital Signatures (DS), i.e., the sender authenticates herself **only** to the receiver by providing a randomized digital signature.
- [ECIES](#ecies): **WIP - DO NOT USE THIS YET**

## Configuration

As was previously noted, ECIES provides a wide range of flexibility in terms of its concrete instantiation. In the following, we provide an overview of its configuration options, or abstract functions:
1. Key agreement (KA)
1. Key derivation function (KDF)
1. Hash function
1. Symmetric cipher
1. Keyed-hash message authentication code (KMAC)

We wish to preserve this property across all implementations provided here. To this end, we expose to developers an object that will allow them to configure the respective module according to their (use case) requirements. Moreover, this allows us to abstract the dependency on JS's `crypto` API. Put simply, if you have another cryptographic library that you more comfortable with, or prefer using, with a little bit of coding, you will be able to use it. Lastly, we do not expect that all developers that will use this library will have the ability to reason about the security of their choices in terms of configuration. Hence, across all implementations, we provide default configuration parameters, which were selected by prioritizing security first. These defaults were chosen based on the seminal work that introduced [DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf), standards specifications (ANSI X9.63, IEEE 1363a, ISO/IEC 18033-2 and SECG SEC1), as well as, the implementation guidelines of [Martinez et al.](https://www.tic.itefi.csic.es/CIBERDINE/Documetos/Cryptologia%20-%20Security%20and%20practical%20considerations%20when%20implementing%20ECIES%20-%20v1.0.pdf)



# ECIESDS
In this version of the implementation, the main idea is that we use a digital signature to authenticate the sender of the message to the receiver. However, we really don't want a man-in-the-middle (MITM) to be able to infer the public key of the sender. Indeed, we only want the receiver of the message to be able to infer the public key of the sender. A high-level description of how we achieve this is as follows. First, we encode in the ciphertext the public key of the sender (details are provided below). Since ECIES is based on ephemeral shared secrets, it (hopefully) is obvious to you that even if the same sender (public key) sends the same message to the same receiver, the ciphertext will always have a different value (in the honest sender setting of course). Second, the sender computes a digital signature by concatenating the output of the keyed message authentication code (KMAC) function (referred to as `tag`, see below) with the ECDH ephemeral secret. Since the ECDH ephemeral secret can only be computed by the receiver and is unique for each message, even if we assume a MITM that has a list of all the public keys in the world, the attacker is not be able to infer the public key of the sender. Conceptually, we have this *weird* asymmetric cryptographic authenticator construction.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which `Alice` wants to send a message to `Bob`:

```js
const eciesds = require('./eciesds') // import the ECIESDS module

// The next two lines are required to properly import the pskcrypto module
$$ = {Buffer}; 
const pskcrypto = require('./pskcrypto'); 

let keyGenerator = pskcrypto.createKeyPairGenerator(); //factory method for EC key pairs
let aliceECKeyPair = keyGenerator.generateKeyPair(); //generate Alice's EC key pair
let bobECKeyPair = keyGenerator.generateKeyPair(); //generate Bob's EC key pair

// We have to convert Alice's key pair to PEM format because that's what the encryption function expects.
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

const plainTextMessage = "hello world"; //the message that Alice wants to send to Bob

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = eciesds.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, plainTextMessage)

// .... Message is transmitted to Bob somehow

// Bob calls the decryption function and gets back an object.
let decEnvelope = eciesds.decrypt(bobECKeyPair.privateKey, encEnvelope)
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);
```
This code sample is based on the one provided in the `example-eciesds.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, i.e., `encrypt()` and `decrypt()`. Assuming the module's default configuration options (documented later on), all values are `base64` encoded.

>### encrypt(senderECKeyPairPEM, receiverECPublicKeyDER, message)
- #### **senderECKeyPairPEM**: An object with properties `publicKey` and `privateKey` wrapping an asymmetric EC key pair. The keys are assumed to be in PEM format.
- #### **receiverECPublicKeyDER**: The EC public key of the receiver in DER format.
- #### **message**: Evidently, the message that we want to encrypt as a **string** type (lol, JS and types).
- #### **Returns**:  An encrypted envelope object (described below)

The encrypted envelope object returned by this function has the following structure:

```json
{
  "to": "BGPsbspekGbi09bnl2CnhMlKG90EQZbPOg85TuDnbLm6E4BELDA8HZoSNgXbkPV68PwzeHO1LIFKbJUJjLpl5UE=",
  "r": "BNIgR9BTXUEXTsyLMMNRaulX0XpGEKW9VUQq7VvQo/cvx2GmXyAicrMWE2LKlL6nyvVIH6RLGUr4pRpbjjuTlvA=",
  "ct": "VQjzWrHP68Ht2t0SYbWFQ8zTBY88uR7/i8HuqB4d/bsXLP3diLFBJWAcCI624uiIp1SrF/y5eXGvxqx2Cmf7BZWFpxjITkzPssWMqZzUrClQMSjtqVIIAJUQlCBMrsoVVTY1da6nNz5gkkI23cKzpJhInFh+2r1VNe7zNLCpBifuX8CXQMFPmyj2PUxJCq+wleWPWVeqFreL/ByC/dcqL3q/RZ4+ZJADZ9wRZll6IdlgHZ0DmMpyu4NyQyin7zhlOuABa+VaU7QTcXslKpEEeQ==",
  "iv": "DEqhcfpCwnpdyjqGD8v1Iw==",
  "tag": "hhmPiBdKbpg9naoEFqsVDdpcI0kqjTpJ9CvP5Caz2zs=",
  "sig": "MEUCIQDbbov8L/iM7V+KwNiy84fCIqMB0Qc/UO00nB+pucaXUQIgb4ZW4MRqAPVTDTA5f4/eRS/DzcN4hiLDqrRyokmYtJc="
}
```
A descriptive overview of the fields of an encrypted envelope object (assuming the default configuration options) is as follows:
1. `to`: The public key of the receiver..
1. `r`: The ephemeral ECDH public key.
1. `ct`: The ciphertext.
1. `iv`: The initialization vector of the symmetric cipher.
1. `tag`: The output of the KMAC function.
1. `sig`: The sender's digital signature.

We now shift our attention to the decryption function, which is defined as follows:

>### decrypt(receiverPrivateKeyDER, encEnvelope)
- #### **receiverPrivateKeyDER**: The private key (in DER format) that corresponds to the one encoded in the `to` field of the input encrypted envelope.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function (described above).
- #### **Returns**:  An object (don't know how to call this, it's described below)

The object that is output by the `decrypt()` function is as follows:
```json
{
    "from": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEbcUJt65Ds9fhvZwlf0ONArf1EoZGSyIk\ni4YGqSulscTxvj/SnDPaczHdVJZhe/hmEbhIcLRMUj8shmeoEn33KQ==\n-----END PUBLIC KEY-----",
    "message": "hello world"
}
```
The `from` field contains the PEM encoded public key of the sender and the `message` field contains the data transmitted by the sender.

## Configuration

In this section, we elaborate on the configuration options that are exposed

. Broadly speaking,
In this section, we document the 

```js
{
  cryptoOptions: {
    hashFunctionName: 'sha256',
    hashSize: 32,
    macKeySize: 16,
    curveName: 'secp256k1',
    signHashFunctionName: 'sha256',
    symmetricCipherName: 'aes-128-cbc',
    symmetricCipherKeySize: 16,
    ivSize: 16
  },
  encodingFormat: 'base64',
  getRandomBytes: crypto.randomBytes,
  evaluateKDF: KDF2,
  symmetricEncrypt: symmetricEncrypt,
  symmetricDecrypt: symmetricDecrypt,
  computeKeyedMAC: computeKeyedMAC,
  verifyKeyedMAC: verifyKeyedMAC,
  computeDigitalSignature: computeDigitalSignature,
  verifyDigitalSignature: verifyDigitalSignature,
  senderComputeECDHValues: senderComputeECDHValues,
  receiverComputeECDHSharedSecret: receiverComputeECDHSharedSecret
};
```
The default key derivation function is [KDF2](https://www.shoup.net/iso/std6.pdf)

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-eciesds.js` file. You can tune the number and size of messages by modifying the `msgNo` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
ECIESDS Benchmark Inputs: 5000 messages, message_size = 100 bytes
Encryption benchmark results: total_time = 14.069853013 (secs), throughput = 355.36973949764746 (ops/sec), Avg_Op_Time = 0.0028139706025999997 (secs)
Decryption benchmark results: total_time = 13.747416197 (secs), throughput = 363.70470845940594 (ops/sec), Avg_Op_Time = 0.0027494832394 (secs)
```
for `msgNo=5000` and `msgSize=100` in my crappy VM. I assume that the output is self-explanatory.

# ECIES - **DO NOT USE THIS RIGHT NOW**
In case you missed the big bold headline above, allow me to reiterate.

<span style="font-size:4em;">**DO NOT USE THE ECIES MODULE**</span>

# Test Cases
