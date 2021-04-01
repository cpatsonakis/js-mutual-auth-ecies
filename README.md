# js-mutual-auth-ecies
The Diffie-Hellman Integrated Encryption Scheme ([DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf)), or the Elliptic Curve Integrated Encryption Scheme ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)), as it is commonly referred to due to its most prominent instantiation based on elliptic curve-based groups, is a construction of a hybrid encryption scheme that has a wide array of attractive security properties. Examples include, semantic security against CCA and CCP enabled adversaries in the **standard model**. Moreover, ECIES provides several features that are important from a practical perspective, i.e., that are relevant to implementers/developers, such as efficiency, flexibility in terms of the employed cryptographic group, the symmetric encryption scheme, KMAC scheme and hash functions, as well as, an arbitrary message space.

In this repository, we provide several different JavaScript implementations of ECIES. A subset of the implementations have **the added property that the message sender authenticates herself to the receiver (and only to the receiver). We stress that this is not the case in the standard ECIES scheme.** Hence, this repo was named `js-mutual-auth-ecies`. Although, in retrospect, we regretted the name choice as it is slightly misleading.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated with the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. To ensure compatibility with the OpenDSU codebase, the implementations provided here depend on the `pskcrypto` module of OpenDSU which, for your convenience dear sir/madam/wherever-in-the-gender-spectrum-you-are, is provided here! We stress, however, that the involvement of the `pskcrypto` module relates **only** to key generation and converting keys to PEM format. Therefore, conceptually, one can easily strip `pskcrypto` entirely from the code base provided here with minimal effort. For a more elaborate description of the issues and our (unfortunate) experiences with JavaScript's `crypto` module, we refer the interested reader to the [Notes on JavaScript's Crypto API](#notes-on-javascript\'s-crypto-api) section of this documentation.

# Overview
A subset of the implementations include the acronym *DOA* in their name, which stands for data origin authentication. Put simply, these implementations also authenticate the sender of the message to the receiver (and only to the receiver). In the following, we provide a succinct overview of the ECIES implementations that are provided in this repository, namely:

- [ECIES-DOA-DS](#ecies-doa-ds): This acronym stands for ECIES data origin authentication with digital signatures (DS), i.e., the sender authenticates herself **only** to the receiver by providing a randomized digital signature.
- [ECIES-DOA-KMAC](#ecies-doa-kmac): This acronym stands for ECIES data origin authentication with keyed message authentication code. In this implementation, the sender uses her private key and the receivers public key to derive a shared ECDH secret. More details in the respective section. **(PENDING SECURITY VALIDATION, DO NOT USE RIGHT NOW)**
- [ECIES](#ecies): This is a standard ECIES implementation which provides for authenticated encryption. Note that in this implementation, the message sender is anonymous. **(NOT IMPLEMENTED YET - FUTURE WORK)**

At this point, one may wonder: Why did we develop multiple implementations that essentially provide the same properties, e.g., `ECIES-DOA-DS` and `ECIES-DOA-KMAC`? Well, the short answer is: for science! We find it interesting to explore multiple avenues in reaching the same goal. On a more practical note, it is useful, in some cases, to have tangible means of assessing the actual performance of different design choices!

# Cryptographic Configuration

## Introduction

As was previously noted, ECIES provides a wide range of flexibility in terms of its concrete instantiation. In the following, we provide an overview of its configuration options, or abstract functions:
1. Key agreement (KA)
1. Key derivation function (KDF)
1. Hash function
1. Symmetric cipher
1. Keyed-hash message authentication code (KMAC)

We wish to preserve this property across all implementations provided here. To this end, we expose to developers an object that will allow them to configure the respective module according to their (use case) requirements. Moreover, this allows us to abstract the dependency on JavaScript's `crypto` module. Put simply, if you have another cryptographic library that you are more comfortable with, or even prefer using, with a little bit of coding, you will be able to use it. Lastly, we do not expect that all developers that will use the code provided here will have the ability to reason about the security of their choices. Hence, we developed a *default* `crypto` module (`crypto/` directory), which is shared across all implementations and was developed by having security as the first priority. The defaults for all the aforementioned abstract functions were chosen based on the seminal work that introduced [DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf), standards' specifications (ANSI X9.63, IEEE 1363a, ISO/IEC 18033-2 and SECG SEC1), as well as, the implementation guidelines of [Martinez et al.](https://www.tic.itefi.csic.es/CIBERDINE/Documetos/Cryptologia%20-%20Security%20and%20practical%20considerations%20when%20implementing%20ECIES%20-%20v1.0.pdf)

In the following, we document and briefly discuss the default instantiation options of the `crypto` module provided here:
1. Key agreement (KA): Elliptic Curve Diffie-Hellman Ephemeral (ECDHE). Although, we note that the implementation provided here allows for plain ECDH as well.
1. Key derivation function (KDF): KDF2 as defined in [ISO/IEC 18033-2](https://www.shoup.net/iso/std6.pdf). To provide for resilience against benign maleability, we refer the reader to the `common` module that illustrates how the input to this function should be computed, based on which we derive the symmetric encryption and KMAC keys.
1. Hash function: SHA-2-256, which is typically referred to as SHA256. However, we consider the latter naming misleading as it does not clearly convey the hash function family and, based on our real-world experience, causes confusion to some developers following the introduction of the Keccak hash function family (SHA-3), which also has a 256 bit instantiation.
1. Symmetric cipher: `AES-128-CBC`. 
1. Keyed-hash message authentication code (KMAC): HMAC construction based on SHA-2-256 and a 128-bit key.

An astute reader (or evidently anyone that reads this statement) may ponder as to why we did not employ a standard authenticated encryption scheme, such as `AES-128-GCM`. It is true that we could have employed, e.g., the `setAAD()` and `setAuthTag()` functions during encryption and decryption, respectively. From a conceptual point of view, we wanted to separate the process of symmetric encryption from that of MAC computation to provide for more flexibility. In addition, it is unclear how the aforementioned API computes the MAC. Are developers supposed to supply the KMAC key in the `setAAD()` function? The documentation does not elaborate on such important details. The only option would be to go through the code base of JavaScript's default `crypto` module, or even worse the underlying OpenSSL C-based library. We obviously did not and will not do that. Naturally, we acknowledge that our choice might incur a slight performance penalty, however, recall that security is our number one priority.

 That being said, it is important at this point to briefly discuss an important issue, i.e., the importance of **using different keys for encryption and KMAC computation**. We have witnessed several cases where implementations employ the same key for both of these processes. We stress, in short, that use of a single key `k` may allow an attacker to modify the ciphertext `ct` -mind you, without even having knowledge of the plaintext- to `ct'`, such that the KMAC will still be valid at the receiver's end. This does not apply to all symmetric cipher suites, however, it is considered best practice among the cryptographic community to use separate keys, or even more generally speaking, that implementers should not use a key (or key pair) for multiple purposes.

## Configuration Options

The `crypto` module provided here exposes the following object (defined in `crypto/index.js`) that provides developers the necessary means to "replace" the default functions with ones of their choice:
```js
{
    encodingFormat: 'base64',
    getRandomBytes: crypto.randomBytes,
    computeDigitalSignature: sig.computeDigitalSignature,
    verifyDigitalSignature: sig.verifyDigitalSignature,
    symmetricEncrypt: cipher.symmetricEncrypt,
    symmetricDecrypt: cipher.symmetricDecrypt,
    KMAC: kmac,
    ECEphemeralKeyAgreement: ecephka,
    KDF: kdf.KDF2,
    params: {
        symmetricCipherKeySize: config.symmetricCipherKeySize,
        macKeySize: config.macKeySize,
        ivSize: config.ivSize,
    }
}
```
In the following, we elaborate on the concrete meaning of all these options.

>### encodingFormat 
- #### **Description:** String value denoting how, e.g., JS Buffers should be converted to string values.
<br>

>### getRandomBytes(size)
- #### **Description:** A cryptographically strong source of entropy/randomness. We employ the `randomBytes()` function of JavaScript's `crypto` module as the default.
- #### **size**: The amount of bytes to generate.
- #### **Returns**:  A randomized Buffer.
<br>

>### computeDigitalSignature(privateKeyPEM, buffer)
- #### **Description:** Compute an ECDSA digital signature on the input buffer.
- #### **privateKeyPEM**: The signing private key in PEM format.
- #### **buffer**: A buffer that contains the data to be signed.
- #### **Returns**:  The computed ECDSA digital signature.

We note that digital signatures, by default, employ the SHA-2-256 hash function (refer to `crypto/config.js` for a complete list of cryptographic parameters)
<br>
<br>

>### verifyDigitalSignature(publicKeyPEM, signature, buffer)
- #### **Description:** ECDSA digital signature verification algorithm.
- #### **publicKeyPEM**: The public signature verification key in PEM format.
- #### **signature**: The ECDSA digital signature as Buffer.
- #### **buffer**: A buffer that contains the data based on which the signature was computed.
- #### **Returns**:  A boolean value indicating whether the input signature is valid (`true`) based on the remaining provided inputs, or not (`false`).
<br>

>### symmetricEncrypt(key, plaintext, iv)
- #### **Description:** Symmetric encryption algorithm.
- #### **key**: The symmetric encryption key as a Buffer.
- #### **plaintext**: A Buffer that contains the data that will be used to produce the ciphertext.
- #### **iv**: The cipher's initialization vector (IV), a common parameter for the overwhelming majority of symmetric ciphers. Internally, the ECIES implementations of `encrypt()` generate cryptographically random and fresh IVs for each encrypted payload, so this is not "directly visible" to developers.
- #### **Returns**:  The computed ciphertext as a Buffer.
<br>

>### symmetricDecrypt(key, ciphertext, iv)
- #### **Description:** Symmetric decryption algorithm.
- #### **key**: The symmetric decryption key as a Buffer. It should be the same as the one that was used for encryption, although again this is handled internally by the ECIES implementations of `decrypt()` and, thus, is not visible to developers.
- #### **ciphertext**: A Buffer that contains the ciphertext that will be used to produce the plaintext.
- #### **iv**: The cipher's initialization vector (IV), which is transmitted by the sender along with the ciphertext and the KMAC.
- #### **Returns**:  The plaintext as a Buffer.

The `KMAC` property is an object that provides two callable functions, which are as follows:
<br>

>### computeKMAC(key, data)
- #### **Description:** Computes a message authentication code (MAC) based on the input key and the data for which we want to provide message integrity.
- #### **key**: The key, as a Buffer, that will be produced as input to the computation of the MAC.
- #### **data**: A Buffer that contains the data (ciphertext) that we want to provide integrity for.
- #### **iv**: The cipher's initialization vector (IV), a common parameter for the overwhelming majority of symmetric ciphers. Internally, the ECIES implementations of `encrypt()` generate cryptographically random and fresh IVs for each encrypted payload, so this is not "directly visible" to developers.
- #### **Returns**:  The computed MAC as a Buffer, to which we interchangeably refer to as a `tag` as well.
<br>

>### verifyKMAC(tag, key, data)
- #### **Description:** Verification algorithm for message authentication codes, which allows us to infer if the data (ciphertext) were tampered with during transit.
- #### **tag**: The MAC, as a Buffer, as was computed and transmitted by the sender.
- #### **key**: The key, as a Buffer, that will be produced as input to the computation of the MAC. It has to be the same as the one that was used to compute the MAC.
- #### **data**: A Buffer that contains the data (ciphertext) against which we want to verify the input MAC.
- #### **Returns**:  A boolean value indicating whether the input MAC (`tag`) is valid (`true`) based on the remaining provided inputs, or not (`false`).

The `ECEphemeralKeyAgreement` property is essentially a class that provides an interface that can be used to perform both plain ECDH, as well as, ECDHE. Internally, the default implementation employs the `ECDH` functionalities of JavaScript's `crypto` module. The following callable functions are provided:
<br>

>### generateEphemeralPublicKey()
- #### **Description:** An integral part of the encryption process of ECIES is the generation of an ephemeral asymmetric key pair, which is subsequently used to derive a shared secret (refer to the following function) based on the public key of the receiver.
- #### **Returns**:  An ephemeral (freshly-generated) ECDH public key as a Buffer.

<br>

>### generateSharedSecretForPublicKey(theirECPublicKey)
- #### **Description:** This function should be called **exactly after** the `generateEphemeralPublicKey()` function (described above) to generate the shared secret that is, subsequently, used to derive the symmetric encryption key and the KMAC key.
- #### **theirECPublicKey**: The EC public key of the receiver as a Buffer.
- #### **Returns**:  The shared secret as a Buffer.

<br>

>### computeSharedSecretFromKeyPair(myECPrivateKey, theirECPublicKey)
- #### **Description:** This function is, typically, invoked by the receiver to compute the shared secret, which will, subsequently, allow her to derive the symmetric encryption key and the MAC key.
- #### **myECPrivateKey**: The receiver's private key as a Buffer.
- #### **theirECPublicKey**: The ephemeral public key as a Buffer. This is transmitted to the receiver in plaintext by the sender.
- #### **Returns**: The shared secret as a Buffer.

Note that all the aforementioned functions will throw an `Error()` if, for instance, any of the input keys are invalid for the specific curve (by default, the `secp256k1` curve is employed).

The `KDF` property of the default cryptographic configuration points to the implementation of the `KDF2` function (refer to `crypto/kdf.js` for implementation details). In the future, we may extend the set of KDF implementations. The signature of the function is as follows:
<br>

>### KDF(x, outputByteSize[, hashFunction = config.hashFunctionName][, hashSize = config.hashSize])
- #### **Description:** A cryptographically secure key derivation function (KDF). The default implementation employs KDF2, which is defined in ISO/IEC 18033-2.
- #### **x**: A Buffer based on which the KDF will produce its expanded (derived) output.
- #### **outputByteSize**: An integer indicating the size of the desired output.
- #### **hashFunction**: The hash function that will be used by the KDF, defaults to SHA-2-256 currently.
- #### **hashSize**: The output size, in bytes, of the employed hash function as an integer.
- #### **Returns**: The expanded output as a Buffer.

Lastly, the `params` property of the default cryptographic configuration contains values that are required by the encryption and decryption algorithms of ECIES implementations. These are as follows:

- `symmetricCipherKeySize`: The byte size of the symmetric cipher's key. Since the default implementation employs `AES-128-CBC`, it's set to 16 bytes (128 bits).
- `macKeySize`: The byte size of the key that will be input to the KMAC algorithms. Defaults to 16 bytes (128 bits).
- `ivSize`: The byte size of the symmetric cipher's IV which, for block ciphers, is equal to the size of the cipher's block, i.e., in 16 bytes (128 bits) for AES.

The `symmetricCipherKeySize` and `macKeySize` are required by the encryption and decryption algorithms of ECIES to compute the `outputByteSize` of the KDF. The `ivSize` is required by the encryption algorithm of ECIES to produce a sufficiently large and cryptographically random IV that will be used as input to the symmetric encryption algorithm.

# ECIES-DOA-DS
In this version of the implementation, the main idea is that we use a digital signature to authenticate the sender of the message to the receiver. However, we really don't want a man-in-the-middle (MITM) to be able to infer the public key of the sender. Indeed, we only want the receiver of the message to be able to infer the public key of the sender. A high-level description of how we achieve this is as follows. First, we encode in the ciphertext the public key of the sender (details are provided below). Since ECIES is based on ephemeral shared secrets, it (hopefully) is obvious that even if the same sender (public key) sends the same message to the same receiver, the resulting ciphertext will always have a different byte representation, or value (in the honest sender setting of course). Second, the sender computes a digital signature by concatenating the output of the KMAC function (or `tag`) with the ECDHE secret. Since the ECDHE secret can only be computed by the receiver and is unique for each message, even if we assume a MITM that has a list of all the public keys in the world, the attacker is not be able to infer the public key of the sender. Conceptually, we have this *weird* asymmetric cryptographic authenticator construction.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which `Alice` wants to send a message to `Bob`:

```js
const ecies = require('./ecies-doa-ds') //import the ECIES module
const assert = require('assert').strict;
// The next two lines are required to properly import and initialize the pskcrypto module
$$ = {Buffer}; 
const pskcrypto = require("./pskcrypto");
// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');
let keyGenerator = pskcrypto.createKeyPairGenerator(); // Object that allows us to generate EC key pairs
let aliceECKeyPair = keyGenerator.generateKeyPair(); // Generate Alice's EC key pair (message sender)
let bobECKeyPair = keyGenerator.generateKeyPair(); // Generate Bob's EC key pair (message receiver)

// We have to convert Alice's key pair to PEM format because that's what the encryption function expects
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, plainTextMessage)

// .... Message is transmitted to Bob somehow

// Bob calls the decryption function and gets back an object.
let decEnvelope = eciesds.decrypt(bobECKeyPair.privateKey, encEnvelope)
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);
```
This code sample is based on the one provided in the `example-ecies-doa-ds.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, i.e., `encrypt()` and `decrypt()` (assuming the default configuration options that were previously discussed), which are defined as follows:
<br>

>### encrypt(senderECKeyPairPEM, receiverECPublicKey, message)
- #### **Description:** A cryptographically secure key derivation function (KDF). The default implementation employs KDF2, which is defined in ISO/IEC 18033-2.
- #### **senderECKeyPairPEM**: An object with properties `publicKey` and `privateKey` that encompass the sender's EC key pair. Both keys should be in PEM format.
- #### **receiverECPublicKey**: The EC public key of the receiver as a Buffer. **Note** that this is not in a standardized format, i.e., DER or PEM. In short, this key should be in the same form as the ones returned by JavaScript's ECDH `crypto.generateKeys()` method, which, in short is a stripped version of DER encoding after removing the first 23 bytes. Refer to the [Notes on JavaScript's Crypto API](#notes-on-javascript\'s-crypto-api) section for more information.
- #### **message**: The message as a Buffer that we want to encrypt and send across the wire.
- #### **Returns**:  An encrypted envelope object (described below).

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons, e.g., improperly formatted keys, keys that are not on the configured curve etc. The encrypted envelope object returned by this function has the following structure:

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
1. `to`: The receiver's encoded public key.
1. `r`: The encoded ECDHE public key.
1. `ct`: The encoded ciphertext.
1. `iv`: The initialization vector of the symmetric cipher in encoded form.
1. `tag`: The output of the KMAC function in encoded form.
1. `sig`: The sender's digital signature in encoded form.

The receiver of an encrypted envelope needs to infer which specific EC private key she should input to the decryption function. To achieve this, the receiver is, typically, expected to decode the `to` field of the received envelope and query w/e database she uses for key storage. Clearly, if the corresponding key cannot be located, the envelope should be discarded as the decryption function will throw an error. The signature of the decryption function is as follows:

>### decrypt(receiverPrivateKey, encEnvelope)
- #### **receiverPrivateKey**: The private key that corresponds to the one encoded in the `to` field of the input encrypted envelope. Regarding the format of this key, we refer the reader to our notes on the `receiverECPublicKey` of the `encrypt()` function.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function.
- #### **Returns**:  An Object with two properties containing the sender's EC public key in PEM format and the transmitted message as a Buffer.

The object that is output by the `decrypt()` function is as follows:
```json
{
    "from": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEbcUJt65Ds9fhvZwlf0ONArf1EoZGSyIk\ni4YGqSulscTxvj/SnDPaczHdVJZhe/hmEbhIcLRMUj8shmeoEn33KQ==\n-----END PUBLIC KEY-----",
    "message": <Buffer 68 65 6c 6c 6f 20 77 6f 72 6c 64>
}
```
The `from` field contains the PEM encoded public key of the sender and the `message` field contains the data transmitted by the sender. This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons.

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-ecies-doa-ds.js` file. You can tune the number and size of messages by modifying the `msgNo` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
ECIES-DOA-DS Benchmark Inputs: 500 messages, message_size = 100 bytes
Encryption benchmark results: total_time = 1.451398416 (secs), throughput = 344.49534634189655 (ops/sec), Avg_Op_Time = 0.0029027968319999997 (secs)
Decryption benchmark results: total_time = 1.437747878 (secs), throughput = 347.7661192555765 (ops/sec), Avg_Op_Time = 0.002875495756 (secs)
```
for `msgNo=500` and `msgSize=100` in my crappy VM. I assume that the output is self-explanatory.

# ECIES-DOA-KMAC

<span style="font-size:3em;">**WIP, DO NOT USE THIS MODULE YET**</span>

# ECIES

<span style="font-size:3em;">**PENDING IMPLEMENTATION**</span>

# Test Cases

**WIP, Expand test cases**

# Notes on JavaScript's Crypto API

To our (unfortunate) surprise, JavaScript's `crypto` module does not allow EC key pairs generated by, e.g., the `generateKeyPairSync()` function, to be used for ECDH (obviously on the same curve). From a theoretical cryptography point of view, this is completely nonsensical. Furthermore, the thrown exception's message is, in all honesty, wrong and, more importantly, misleading for implementers that do not have solid knowledge of elliptic curve cryptography (ECC). **WIP**


# To-Do List

- [ ] There is a need for a unified key format. Some functions require PEM formatted keys, others use binary point representation (not DER). This is kinda messy.
- [ ] An extension to the previous point is that this unified format should be extended to how keys are encoded in communicated messages and the envelope that is output by, e.g., the decryption function.
- [ ] We need a "proper" library for EC point operations. This will allow us to explore other options for ECIES implementations, such as ECDH co-factor. 
- [ ] At some point in time, the `pskcrypto` dependency should be removed to constitute the code provided here as self-contained as possible.
- [ ] Explore and evaluate the degree in which operations can be parallelized.
- [ ] Expand the provided API to allow for optional callbacks.


