# js-mutual-auth-ecies
The Diffie-Hellman Integrated Encryption Scheme ([DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf)), or the Elliptic Curve Integrated Encryption Scheme ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)), as it is commonly referred to due to its most prominent instantiation over elliptic curve-based groups, is a construction of a hybrid authenticated encryption scheme that has a wide array of attractive security properties. Examples include, semantic security against CCA and CCP enabled adversaries in the **standard model**. Moreover, ECIES has several features that are important from a practical perspective, i.e., that are relevant to implementers/developers, such as efficiency, flexibility in terms of the employed elliptic curve, the symmetric encryption and KMAC scheme, the hash function, as well as, an arbitrary message space.

In this repository, we provide several different NodeJS implementations of ECIES. A subset of the implementations have **the added property that the message sender authenticates herself to the receiver (and only to the receiver). We stress that this is not the case in the standard ECIES scheme.** Hence, this repo was named `js-mutual-auth-ecies`. Although, in retrospect, we regretted the name choice as it is slightly misleading.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated in the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. Initial releases of this repository depended on the [pskcrypto](https://github.com/PrivateSky/pskcrypto) module to ensure compatibility with the OpenDSU codebase. This dependency was, later on, dropped to constitute the code base provided here as self-contained as possible. The implementations in this repository employ, in the background, NodeJS's `crypto` module, which is essentially a wrapper of the OpenSSL C-based library implementation.

# Overview
A subset of the implementations include the acronym *DOA* in their name, which stands for data origin authentication. Put simply, these implementations also authenticate the sender of the message to the receiver (and only to the receiver). In the following, we provide a succinct overview of the ECIES implementations that are included in this repository:

- [ECIES-DOA-DS](#ecies-doa-ds): This acronym stands for ECIES data origin authentication with digital signatures (DS), i.e., the sender authenticates herself **only** to the receiver by digitally signing the ephemeral shared secret.
- [ECIES-DOA-KMAC](#ecies-doa-kmac): This acronym stands for ECIES data origin authentication with keyed message authentication code. In this implementation, the sender uses her private key and the receiver's public key to derive a shared ECDH secret. More details are provided in the respective section. **(PENDING SECURITY VALIDATION, DO NOT USE RIGHT NOW)**
- [ECIES](#ecies): This is a standard ECIES implementation, which provides for authenticated encryption. Note that in this implementation, the message sender is anonymous.

At this point, one may wonder: Why did we develop multiple implementations that essentially provide the same properties, e.g., `ECIES-DOA-DS` and `ECIES-DOA-KMAC`? Well, the short answer is: for science! We find it interesting to explore multiple avenues in reaching the same goal. On a more practical note, it is useful, in some cases, to have tangible means of assessing the actual performance of different design choices!

# Cryptographic Configuration

## Introduction

As was previously noted, ECIES provides a wide range of flexibility in terms of its concrete instantiation. In the following, we provide an overview of its configuration options, or abstract functions:
1. Key agreement (KA)
1. Key derivation function (KDF)
1. Hash function
1. Symmetric cipher
1. Keyed message authentication code (KMAC)

We wish to preserve ECIES's instantiation flexibility across all implementations provided here. To this end, we expose to developers an object that allows them to configure the respective module according to their (use case) requirements. Moreover, this allows us to abstract the dependency on NodeJS's `crypto` module. Put simply, if you have another cryptographic library that you are more comfortable with, or even prefer using, with a little bit of coding, you will be able to use it. Lastly, we do not expect that all developers that will use the code provided here will have the ability to reason about the security of their choices. Hence, we developed a *default* `crypto` module (`crypto/` directory), which is shared across all implementations and was developed by having security as the first priority. The defaults for all the aforementioned abstract functions were chosen based on the seminal work that introduced [DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf), standards' specifications (ANSI X9.63, IEEE 1363a, ISO/IEC 18033-2 and SECG SEC1), as well as, the implementation guidelines of [Martinez et al.](https://www.tic.itefi.csic.es/CIBERDINE/Documetos/Cryptologia%20-%20Security%20and%20practical%20considerations%20when%20implementing%20ECIES%20-%20v1.0.pdf)

In the following, we document and briefly discuss the default instantiation options of the `crypto` module provided here:
1. Key agreement (KA): Elliptic Curve Diffie-Hellman Ephemeral (ECDHE). Although, we note that the implementation provided here allows for plain ECDH as well.
1. Key derivation function (KDF): KDF2 as defined in [ISO/IEC 18033-2](https://www.shoup.net/iso/std6.pdf). To provide for resilience against benign maleability, we refer the reader to the `common` module that illustrates how the input to this function should be computed, based on which we derive the symmetric encryption and KMAC keys.
1. Hash function: SHA-2-256, which is typically referred to as SHA256. However, we consider the latter naming convention misleading as it does not clearly convey the hash function family and, based on our real-world experience, causes confusion to some developers following the introduction of the Keccak hash function family (SHA-3), which also has a 256 bit instantiation.
1. Symmetric cipher: `AES-128-CBC`. 
1. Keyed message authentication code (KMAC): HMAC construction based on SHA-2-256 and a 128-bit key.

An astute reader (or evidently anyone that reads this statement) may ponder as to why we did not employ a standard authenticated encryption scheme, such as `AES-128-GCM`. It is true that we could have employed, e.g., the `setAAD()` and `setAuthTag()` functions during encryption and decryption, respectively. From a conceptual point of view, we wanted to separate the process of symmetric encryption from that of MAC computation to provide for more flexibility. In addition, it is unclear how the aforementioned API of NodeJS's `crypto` module computes the MAC. Are developers supposed to supply the KMAC key in the `setAAD()` function? The documentation does not elaborate on such important details. The only option to infer such important information would be to go through the code base of NodeJS's default `crypto` module, or even worse, the underlying OpenSSL C-based library implementation. We obviously did not and will not do that. Naturally, we acknowledge that our choice might incur a slight performance penalty, however, recall that security is our number one priority.

## Note on Cryptographic Keys

As a starting point, we begin by stressing the importance of **using different keys for encryption and KMAC computation**. We have witnessed several cases where readily available implementations on the web employ the same key for both of these processes. We stress, in short, that use of a single key `k` may allow an attacker to modify the ciphertext `ct` -mind you, without even having knowledge of the plaintext- to `ct'`, such that the KMAC will still be valid at the receiver's end. This does not apply to all symmetric cipher suites, however, it is considered best practice among the cryptographic community to use separate keys, or even more generally speaking, that implementers should **not** use a key (or key pair) for multiple purposes.

Overall, and as was hinted in the previous section, the code bases provided here employ keys for several distinct functionalities, e.g., key agreement and digital signatures.  Hence, it is relevant for, e.g., developers, to briefly discuss the types (in programming language terms) of these keys, as well as, their serialization format when they are transmitted over the wire. The default implementations of the cryptographic algorithms employ NodeJS's `crypto` module in the background, thus, the points discussed below will be based on this fact. Key agreement keys that are input to, or output from, various functions are expected to comply to the format that is output by the `ECDH` class which, in short, are of type `Buffer` and, in the interest of clarity, we stress that they **do not comply** to any standardized key encoding, e.g., DER. ECDH public keys are serialized as `base64` encoded strings. Regarding EC key pairs for computing and verifying digital signatures, the crypto defaults expect `KeyObject` types. Public EC signature verification keys are serialized by, first, exporting them (via `KeyObject.export()`) in DER format and, subsequently, encoding them as `base64` encoded strings. Lastly, we do not discuss symmetric and KMAC keys here as these are handled internally in the ECIES encryption and decryption functions and are, thus, not directly exposed to developers.

We conclude this section by stressing that we have noticed a tremendous inconsistency in regards to how keys are handled and formatted by NodeJS's `crypto` module. For the interested reader, we have documented our (unfortunate) experiences with this module in the [NotesJSCrypto.md](NotesJSCrypto.md) file.

## Configuration Options

The `crypto` module provided here exposes the following object (defined in `crypto/index.js`) that provides developers the necessary means to "replace" the default functions with ones of their choice:
```js
{
    encodingFormat: 'base64',
    timingSafeEqual: crypto.timingSafeEqual,
    getRandomBytes: crypto.randomBytes,
    computeDigitalSignature: sig.computeDigitalSignature,
    verifyDigitalSignature: sig.verifyDigitalSignature,
    symmetricEncrypt: cipher.symmetricEncrypt,
    symmetricDecrypt: cipher.symmetricDecrypt,
    KMAC: kmac,
    ECEphemeralKeyAgreement: require('./ecephka'),
    KDF: kdf.KDF2,
    PublicKeySerializer: require('./pkserializer'),
    PublicKeyDeserializer: require('./pkdeserializer'),
    params: {
        symmetricCipherKeySize: config.symmetricCipherKeySize,
        macKeySize: config.macKeySize,
        ivSize: config.ivSize,
        curveName: 'secp256k1'
    }
}
```
In the following, we elaborate on the concrete meaning of all these options.

>### encodingFormat 
- #### **Description:** String value denoting how, e.g., `Buffer` types should be converted to (encoded as) string values.
<br>

>### timingSafeEqual(a, b)
- #### **Description:** Constant-time equality evaluation algorithm that is suitable for cryptographic applications. We employ the `timingSafeEqual()` function of NodeJS's `crypto` module as the default.
- #### **a**: The first input value, typically of type `Buffer`.
- #### **b**: The second input value, typically of type `Buffer`.
- #### **Returns**:  A boolean value that will be set to `true` if `a` is equal to `b`, or `false` otherwise.
<br>

>### getRandomBytes(size)
- #### **Description:** A cryptographically strong source of entropy/randomness. We employ the `randomBytes()` function of NodeJS's `crypto` module as the default.
- #### **size**: The amount of bytes to generate.
- #### **Returns**:  A randomized `Buffer`.
<br>

>### computeDigitalSignature(privateECSigningKey, buffer)
- #### **Description:** Digitally sign the input buffer, which is of type `Buffer`.
- #### **privateECSigningKey**: The signing EC private key that will be used to compute the digital signature.
- #### **buffer**: The data to be signed as a `Buffer` type.
- #### **Returns**:  The computed digital signature as a `Buffer` type.
<br>

>### verifyDigitalSignature(publicECVerificationKey, signature, buffer)
- #### **Description:** Digital signature verification algorithm.
- #### **publicECVerificationKey**: The public verification EC key that will be used to verify the input digital signature.
- #### **signature**: The digital signature as a `Buffer` type.
- #### **buffer**: The data, as a `Buffer` type, against which the signature will be verified.
- #### **Returns**:  A boolean value indicating whether the input signature is valid (`true`), or not (`false`).
<br>

We note that functions related to digital signatures, by default, employ the SHA-2-256 hash function (refer to `crypto/private_config.js` for a complete list of cryptographic parameters).
<br>

>### symmetricEncrypt(key, plaintext, iv)
- #### **Description:** Symmetric encryption algorithm.
- #### **key**: The symmetric encryption key as a `Buffer` type.
- #### **plaintext**: A `Buffer` that contains the data that will be used to produce the ciphertext.
- #### **iv**: The cipher's initialization vector (IV), a common parameter for the overwhelming majority of symmetric ciphers. Internally, the ECIES implementations of `encrypt()` generate cryptographically random and fresh IVs for each encrypted payload, so this is not "directly visible" to developers.
- #### **Returns**:  The computed ciphertext as a `Buffer` type.
<br>

>### symmetricDecrypt(key, ciphertext, iv)
- #### **Description:** Symmetric decryption algorithm.
- #### **key**: The symmetric decryption key as a `Buffer` type. It should be the same as the one that was used for encryption, although again this is handled internally by the ECIES implementations of `decrypt()` and, thus, is not "directly visible" to developers.
- #### **ciphertext**: A `Buffer` that contains the ciphertext that will be used to produce the plaintext.
- #### **iv**: The cipher's initialization vector (IV), which is transmitted by the sender along with the ciphertext and the output of the KMAC function.
- #### **Returns**:  The plaintext as a `Buffer` type.

The `KMAC` property of the module's configuration is an object that provides two callable functions, which are defined as follows:
<br>

>### computeKMAC(key, data)
- #### **Description:** Computes a message authentication code (MAC) based on the input key and the data for which we want to provide message integrity.
- #### **key**: The key, as a `Buffer` type, that will be used as input to the computation of the MAC.
- #### **data**: A `Buffer` that contains the data that we want to provide integrity for.
- #### **Returns**:  The computed MAC as a `Buffer` type, to which we interchangeably refer to as `tag` as well.
<br>

>### verifyKMAC(tag, key, data)
- #### **Description:** Verification algorithm for message authentication codes, which allows us to infer if the data were tampered with during transit.
- #### **tag**: The MAC, as a `Buffer` type, as was computed and transmitted by the sender.
- #### **key**: The key, as a `Buffer` type, that will be used as input to the computation of the MAC.
- #### **data**: A `Buffer` that contains the data against which we want to verify the input MAC.
- #### **Returns**:  A boolean value indicating whether the input MAC (`tag`) is valid (`true`) based on the input data, or not (`false`).

The `ECEphemeralKeyAgreement` property is a class that provides an interface that can be used for ECDH and ECDHE and provides the following callable functions:
<br>

>### generateEphemeralPublicKey()
- #### **Description:** An integral part of the encryption process of ECIES is the generation of an ephemeral asymmetric key pair, which is subsequently used to derive a shared secret (refer to the next function) based on the public key of the receiver.
- #### **Returns**:  An ephemeral ECDH public key.
<br>

>### generateSharedSecretForPublicKey(theirECDHPublicKey)
- #### **Description:** This function should be called **exactly after** the `generateEphemeralPublicKey()` function (described above) to generate the shared secret that is, subsequently, used to derive the symmetric encryption and KMAC keys.
- #### **theirECDHPublicKey**: The ECDH public key of the receiver.
- #### **Returns**:  The shared secret as a `Buffer` type.
<br>

>### computeSharedSecretFromKeyPair(myECDHPrivateKey, theirECDHPublicKey)
- #### **Description:** This function is, typically, invoked by the receiver to compute the shared secret, which will, subsequently, allow her to derive the symmetric encryption and KMAC keys.
- #### **myECDHPrivateKey**: The receiver's private ECDH key.
- #### **theirECDHPublicKey**: The (ephemeral) ECDH public key.
- #### **Returns**: The shared secret as a `Buffer` type.

Note that all the aforementioned functions will throw an `Error()` if, for instance, any of the input keys are invalid for the specific curve (by default, we employ the `secp256k1` curve).

The `KDF` property of the default cryptographic configuration points to the implementation of the `KDF2` function (refer to `crypto/kdf.js` for implementation details). In the future, we may extend the set of KDF implementations. The signature of the function is as follows:
<br>

>### KDF(x, outputByteSize[, hashFunction = config.hashFunctionName][, hashSize = config.hashSize])
- #### **Description:** A cryptographically secure key derivation function (KDF). The default implementation employs KDF2, which is defined in ISO/IEC 18033-2.
- #### **x**: A `Buffer` based on which the KDF will produce its expanded (derived) output.
- #### **outputByteSize**: An integer indicating the size of the desired output.
- #### **hashFunction**: The hash function that will be used by the KDF, defaults to SHA-2-256 currently.
- #### **hashSize**: The output size, in bytes, of the employed hash function as an integer.
- #### **Returns**: The expanded output as a `Buffer` type.

The `PublicKeySerializer` and `PublicKeyDeserializer` properties of the default cryptographic configuration are, essentially, functors whose main purpose is to abstract the serialization and deserialization, respectively, of ECDH and EC public keys. These functors serve as an additional mechanism for abstracting NodeJS's `crypto` module.

The functions exposed by the `PublicKeySerializer` functor are defined as follows:
<br>

>### serializeECDHPublicKey(ecdhPublicKey)
- #### **Description:** Serialization function for ECDH public keys.
- #### **ecdhPublicKey**: An ECDH public key.
- #### **Returns**: The encoded ECDH public key as a `string` type.
<br>

>### serializeECSigVerPublicKey(ecSigVerPublicKey)
- #### **Description:** Serialization function for EC public keys that are used for digital signature verification.
- #### **ecSigVerPublicKey**: An EC public key.
- #### **Returns**: The encoded EC public key as a `string` type.

The functions exposed by the `PublicKeyDeserializer` functor are defined as follows:
<br>

>### deserializeECDHPublicKey(ecdhPublicKeySerialized)
- #### **Description:** Deserialization function for ECDH public keys.
- #### **ecdhPublicKeySerialized**: A serialized ECDH public key, i.e., as it is output by the `PublicKeySerializer.serializeECDHPublicKey()` function.
- #### **Returns**: The deserialized (decoded) ECDH public key.
<br>

>### deserializeECSigVerPublicKey(ecSigVerPublicKeySerialized)
- #### **Description:** Deserialization function for EC public keys that are used for digital signature verification.
- #### **ecSigVerPublicKeySerialized**: A serialized EC public key, i.e., as it is output by the `PublicKeySerializer.serializeECSigVerPublicKey()` function.
- #### **Returns**: The deserialized (decoded) EC public key.

Lastly, the `params` property of the default cryptographic configuration contains values that are required by the encryption and decryption algorithms of ECIES implementations. These are as follows:

- `symmetricCipherKeySize`: The byte size of the symmetric cipher's key. Since the default implementation employs `AES-128-CBC`, it's set to 16 bytes (128 bits).
- `macKeySize`: The byte size of the key that will be input to the KMAC algorithms. Defaults to 16 bytes (128 bits).
- `ivSize`: The byte size of the symmetric cipher's IV which, for block ciphers, is equal to the size of the cipher's block, i.e., 16 bytes (128 bits) for AES.
- `curveName`: The named curve, default is `secp256k1`.

The `symmetricCipherKeySize` and `macKeySize` are required by the encryption and decryption algorithms of ECIES implementations to compute the `outputByteSize` of the KDF. The `ivSize` is required by the encryption algorithm of ECIES to produce a sufficiently large and cryptographically random IV that will be used as input to the symmetric encryption algorithm. The `curveName` is required by the `ECEphemeralKeyAgreement` class and can be modified by clients of this module. **We stress that if client code modifies the value of the named curve, existing instances of the `ECEphemeralKeyAgreement` class should be invalidated and new ones should be created in their place where needed.**

# ECIES-DOA-DS
In this version of ECIES, the main idea is that we use a digital signature to authenticate the sender of the message to the receiver. However, we really don't want a man-in-the-middle (MITM) to be able to infer the public key of the sender. Indeed, we only want the receiver of the message to be able to infer the public key of the sender. A high-level description of how we achieve this is as follows. The ECIES plaintext is comprised by three parts: 1) a digital signature on the ECDHE secret, 2) the sender's EC public key based on which the receiver can verify the digital signature and, 3) the actual message. Since ECIES is based on ephemeral shared secrets and since we use freshly-generated IVs for each transmitted message, it (hopefully) is obvious that even if the same sender (public key) sends the same message to the same receiver, the resulting ciphertext will always have a different byte representation (in the honest sender setting of course). Note also that ECDSA signatures are also randomized, which is another reason for which the resulting ciphertext will be different. In addition, since the ECDHE secret can only be computed by the receiver and is unique for each message, only the receiver can decrypt the ciphertext. Furthermore, since the sender's public key and signature is "hidden" inside the ECIES ciphertext, it is never exposed in transit. Hence, even if we assume a MITM that has a list of all the public keys in the world, the sender's identity is concealed. 

We stress that a malicious receiver `A` can reveal a message's origin to some other party `X` by taking advantage of the non-repudiation property of digital signatures. However, in order for `X` to be unequivocally convinced, `A` is forced to reveal her private key to `X` which, in the general case, we assume that `A` would not want to do as that would allow `X` to impersonate `A` in the future. Lastly, we stress that a malicious receiver `A` cannot use an honest sender's `B` digital signature on some shared ephemeral secret `S` so that `A` can impersonate herself as `B` to some other receiver `C`, without breaking the discrete logarithm problem.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which `Alice` wants to send a message to `Bob`:

```js
const ecies = require('./ecies-doa-ds'); //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('./crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');

// Generate Alice's EC signing key pair
let aliceECSigningKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
// Generate Bob's ECDH key pair (message receiver)
let bobECDH = crypto.createECDH(curveName)
let bobECDHPublicKey = bobECDH.generateKeys(); 
let bobECDHPrivateKey = bobECDH.getPrivateKey();

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(aliceECSigningKeyPair, bobECDHPublicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)

// ... The encrypted envelope is somehow transmitted to Bob
// Bob receives the encrypted envelope
// Bob decodes the ECDH public key for which this encrypted envelope is intended for
let myECDHPublicKey = ecies.getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
// ... Bob searches his key database for the corresponding ECDH private key
// ... We assume here that Bob finds it
assert(Buffer.compare(myECDHPublicKey, bobECDHPublicKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")
// Bob calls the decryption function and gets back an object.
let decEnvelope = ecies.decrypt(bobECDHPrivateKey, encEnvelope)
assert(Buffer.compare(decEnvelope.message, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);
```
This code sample is based on the one provided in the `example-ecies-doa-ds.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, assuming the default cryptographic configuration options that were previously discussed, which are defined as follows:
<br>

>### getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
- #### **Description:** This is a helper function that is intended to be used by the receiver so that he can easily get, on input an encrypted envelope object (described below), the public ECDH key used by the sender of the message.
- #### **encEnvelope**: An encrypted envelope object (described below).
- #### **Returns**:  The deserialized (decoded) ECDH public key.

The receiver of an encrypted envelope needs to infer which specific ECDH private key she should input to the decryption function (described later on in this section). To achieve this, the receiver is, typically, expected to first invoke this function and, subsequently, query w/e database she uses for key storage. Clearly, if the corresponding key cannot be located, the envelope should be discarded as the decryption function will throw an error.
<br>

>### encrypt(senderECSigningKeyPair, receiverECDHPublicKey, message)
- #### **senderECSigningKeyPair**: An object with properties `publicKey` and `privateKey` that encompass the sender's EC signing key pair.
- #### **receiverECDHPublicKey**: The ECDH public key of the receiver.
- #### **message**: The message as a Buffer that we want to encrypt and send across the wire.
- #### **Returns**:  An encrypted envelope object (described below).

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons, e.g., improperly formatted keys, keys that are not on the configured curve etc. The encrypted envelope object returned by this function has the following structure:

```json
{
  "to_ecdh": "BGPsbspekGbi09bnl2CnhMlKG90EQZbPOg85TuDnbLm6E4BELDA8HZoSNgXbkPV68PwzeHO1LIFKbJUJjLpl5UE=",
  "r": "BNIgR9BTXUEXTsyLMMNRaulX0XpGEKW9VUQq7VvQo/cvx2GmXyAicrMWE2LKlL6nyvVIH6RLGUr4pRpbjjuTlvA=",
  "ct": "VQjzWrHP68Ht2t0SYbWFQ8zTBY88uR7/i8HuqB4d/bsXLP3diLFBJWAcCI624uiIp1SrF/y5eXGvxqx2Cmf7BZWFpxjITkzPssWMqZzUrClQMSjtqVIIAJUQlCBMrsoVVTY1da6nNz5gkkI23cKzpJhInFh+2r1VNe7zNLCpBifuX8CXQMFPmyj2PUxJCq+wleWPWVeqFreL/ByC/dcqL3q/RZ4+ZJADZ9wRZll6IdlgHZ0DmMpyu4NyQyin7zhlOuABa+VaU7QTcXslKpEEeQ==",
  "iv": "DEqhcfpCwnpdyjqGD8v1Iw==",
  "tag": "hhmPiBdKbpg9naoEFqsVDdpcI0kqjTpJ9CvP5Caz2zs="
}
```
A succinct overview of the fields of an encrypted envelope object is as follows:
1. `to_ecdh`: The receiver's ECDH public key.
1. `r`: The ECDHE public key.
1. `ct`: The ciphertext.
1. `iv`: The initialization vector of the symmetric cipher.
1. `tag`: The output of the KMAC function.
<br>

>### decrypt(receiverECDHPrivateKey, encEnvelope)
- #### **receiverECDHPrivateKey**: The receiver's ECDH private key that corresponds to the one encoded in the `to_ecdh` field of the input encrypted envelope.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function.
- #### **Returns**:  An Object with two properties, i.e., `from_ecsig`, which contains the EC public verification key of the sender, and `message`, which contains the message as a `Buffer` type.

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons.

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-ecies-doa-ds.js` file. You can tune the number and size of messages by modifying the `msgNo` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
ECIES-DOA-DS Benchmark Inputs: 500 messages, message_size = 100 bytes
Encryption benchmark results: total_time = 1.495617838 (secs), throughput = 334.31000038660943 (ops/sec), Avg_Op_Time = 0.002991235676 (secs)
Decryption benchmark results: total_time = 1.40161524 (secs), throughput = 356.7312809755122 (ops/sec), Avg_Op_Time = 0.0028032304799999997 (secs)
```
for `msgNo=500` and `msgSize=100`, which was executed on a fairly resource-constrained VM.

# ECIES-DOA-KMAC

<span style="font-size:3em;">**WIP, DO NOT USE THIS MODULE YET**</span>

# ECIES
This is an implementation of the standard ECIES hybrid authenticated encryption scheme. We refer the interested reader to the resources that we have already provided in previous (introductory) sections of this documentation for more information.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which some entity (which is always anonymous in this version of the implementation) wants to send a message to `Bob`:

```js
const ecies = require('./ecies'); //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('./crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');

// Generate Bob's ECDH key pair (message receiver)
let bobECDH = crypto.createECDH(curveName)
let bobECDHPublicKey = bobECDH.generateKeys(); 
let bobECDHPrivateKey = bobECDH.getPrivateKey();

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(bobECDHPublicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)

// ... The encrypted envelope is somehow transmitted to Bob
// Bob receives the encrypted envelope
// Bob decodes the ECDH public key for which this encrypted envelope is intended for
let myECDHPublicKey = ecies.getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
// ... Bob searches his key database for the corresponding ECDH private key
// ... We assume here that Bob finds it
assert(Buffer.compare(myECDHPublicKey, bobECDHPublicKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")
// Bob calls the decryption function and gets back the message
let decMessage = ecies.decrypt(bobECDHPrivateKey, encEnvelope)
assert(Buffer.compare(decMessage, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
// Here is the decrypted message!
console.log('Decrypted message is: ' + decMessage);
```
This code sample is provided in the `example-ecies.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, assuming the default configuration options that were previously discussed, which are defined as follows:
<br>

>### getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
- #### **Description:** This is a helper function that is intended to be used by the receiver so that he can easily get, on input an encrypted envelope object (described below), the public ECDH key used by the sender of the message.
- #### **encEnvelope**: An encrypted envelope object (described below).
- #### **Returns**:  The deserialized (decoded) ECDH public key.

The receiver of an encrypted envelope needs to infer which specific ECDH private key she should input to the decryption function (described later on in this section). To achieve this, the receiver is, typically, expected to first invoke this function and, subsequently, query w/e database she uses for key storage. Clearly, if the corresponding key cannot be located, the envelope should be discarded as the decryption function will throw an error.

>### encrypt(receiverECDHPublicKey, message)
- #### **Description:** The encryption function of this ECIES implementation.
- #### **receiverECDHPublicKey**: The ECDH public key of the receiver.
- #### **message**: The message as a Buffer that we want to encrypt and send across the wire.
- #### **Returns**:  An encrypted envelope object (described below).

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons, e.g., improperly formatted keys, keys that are not on the configured curve etc. The encrypted envelope object returned by this function has the following structure:

```json
{
  "to_ecdh": "BD88tJ3mYhEUrWrmMw1dDIdgQrZ5TuilX4n4xKZ9JKpgYRpWl1IUMXW1V02+1h+3W9Qt5mk/UIxBY778zSXc5dE=",
  "r": "BGSEGwR5SwTIAP/5xJWQ5VC0WAXonO6rdSP0BMyUZFgLZ3QyeXQv9aLamlmfS7XiPGKSFWEGEVAsYBh7g+dbefE=",
  "ct": "taNKCNJ4W83MQW/O7uncBw==",
  "iv": "u3PvRck4BwLj2zXqLoDB7w==",
  "tag": "RH+dXUTYfGDTj+sctNJQjbVi9cXRpXE62elWPpB4iAA="
}
```
A succinct overview of the fields of an encrypted envelope object is as follows:
1. `to_ecdh`: The receiver's ECDH public key.
1. `r`: The ECDHE public key.
1. `ct`: The ciphertext.
1. `iv`: The initialization vector of the symmetric cipher.
1. `tag`: The output of the KMAC function.
<br>

>### decrypt(receiverECDHPrivateKey, encEnvelope)
- #### **Description:** The decryption function of this ECIES implementation.
- #### **receiverECDHPrivateKey**:  The receiver's ECDH private key that corresponds to the one encoded in the to_ecdh field of the input encrypted envelope.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function.
- #### **Returns**:  The decrypted message as a `Buffer` type.

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons.

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-ecies.js` file. You can tune the number and size of messages by modifying the `msgNo` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
ECIES Benchmark Inputs: 500 messages, message_size = 100 bytes
Encryption benchmark results: total_time = 1.094277312 (secs), throughput = 456.9225684540191 (ops/sec), Avg_Op_Time = 0.002188554624 (secs)
Decryption benchmark results: total_time = 1.083953257 (secs), throughput = 461.2745030941865 (ops/sec), Avg_Op_Time = 0.002167906514 (secs)
```
for `msgNo=500` and `msgSize=100`, which was executed on a fairly resource-constrained VM.

# Test Cases

**WIP, Expand test cases**

# To-Do List

- [x] There is a need for a unified key format. Some functions require PEM formatted keys, others use binary point representation (not DER). This is kinda messy.
- [x] An extension to the previous point is that this unified format should be extended to how keys are encoded in communicated messages and the envelope that is output by, e.g., the decryption function.
- [ ] We need a "proper" library for EC point operations. This will allow us to explore other options for ECIES implementations, such as ECDH co-factor. 
- [x] At some point in time, the `pskcrypto` dependency should be removed to constitute the code provided here as self-contained as possible.
- [ ] Explore and evaluate the degree in which operations can be parallelized.
- [ ] Expand the provided API to allow for optional callbacks.


