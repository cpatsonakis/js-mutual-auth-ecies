# js-mutual-auth-ecies
The Diffie-Hellman Integrated Encryption Scheme ([DHIES](http://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf)), or the Elliptic Curve Integrated Encryption Scheme ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)), as it is commonly referred to, is a construction of a hybrid encryption scheme that has a wide array of attractive security properties, such as semantic security against CCA and CCP enabled adversaries in the **standard model**. Moreover, ECIES provides several features that are important from a practical perspective, i.e., that are relevant to implementers/developers, such as efficiency, flexibility in terms of the employed cryptographic group, the symmetric encryption scheme, KMAC scheme and hash functions, as well as, an arbitrary message space.

In this repository, a JavaScript (a.k.a trash language) implementation of ECIES is provided, however, **with the added property that the message sender authenticates herself to the receiver (and only to the receiver). We stress that this is not the case in the standard ECIES scheme.** Hence, the reason why this repo is entitled `js-mutual-auth-ecies`.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated with the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. To maintain compatibility with the OpenDSU codebase, the implementation provided here depends on the `pskcrypto` module of OpenDSU which, for your convenience dear sir/madam/wherever-in-the-gender-spectrum-you-are, is provided here!

# STOP! ARE YOU A BRAINDEAD DEVELOPER???
Are you the kind of developer that just wants to call functions and get the job done? You don"t care at all about implementation details? Well well, worry not my friend, we got you covered, we feel you, everything"s cool. In the following, we provide for all you sensitive snowflake developers a simple example in which `Alice` wants to send a message to `Bob`:

```js
const eciesds = require("./eciesds") // import the ECIES module

$$ = {Buffer}; // I have no idea what this thing is, but who cares, surely you shouldn"t.
const pskcrypto = require("./pskcrypto"); //import the PrivateSky crypto module

let keyGenerator = pskcrypto.createKeyPairGenerator(); //factory method for EC key pairs (I guess)
let aliceECKeyPair = keyGenerator.generateKeyPair(); //generate Alice"s EC key pair
let bobECKeyPair = keyGenerator.generateKeyPair(); //generate Bob"s EC key pair

// We have to convert Alice"s key pair from DER (or w/e the hell the default format is) 
// to PEM format because that's what the encryption function expects.
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

const plainTextMessage = "hello world"; //a w/e message that Alice wants to send to Bob

// Encrypt the message and you get a JSON object back that you can send over any communication
// channel you want (e.g., HTTP, WS, smoke signals).
let encEnvelope = eciesds.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, plainTextMessage)

// .... Message is transmitted to Bob somehow

// Bob calls the decryption algorithm and gets back an object.
let decEnvelope = eciesds.decrypt(bobECKeyPair.privateKey, encEnvelope)
// Here is the decrypted message!
console.log("Decrypted message is: " + decEnvelope.message);
```
You can find the code provided above in the `example-eciesds.js` file.

That's all, now you can go on with your life.

# 

# Overview
This repository provides two implementations:

- [ECIESDS](#eciesds): This acronym stands for ECIES with Digital Signatures(DS), i.e., basically we use a randomized digital signature to authenticate the sender of the message to the receiver.
- [ECIES](#ecies): **WIP - DO NOT USE THIS YET**


# ECIESDS
In this version of the implementation, the main idea is that we use a digital signature to authenticate the sender of the message to the receiver. However, we really don't want a man-in-the-middle (MITM) to be able to infer the public key of the sender. Indeed, we only want the receiver of the message to be able to infer the public key of the sender. A high-level description of how we achieve this is as follows. First, we encode in the ciphertext the public key of the sender (details are provided below). Since ECIES is based on ephemeral shared secrets, it (hopefully) is obvious to you that even if the same sender (public key) sends the same message to the same receiver, the ciphertext will always have a different value (in the honest sender setting of course). Second, the sender computes a digital signature by concatenating the output of the keyed message authentication code (KMAC) function (referred to as `tag`, see below) with the ECDH ephemeral secret. Since the ECDH ephemeral secret can only be computed by the receiver and is unique for each message, even if we assume a MITM that has a list of all the public keys in the world, the attacker is not be able to infer the public key of the sender. Conceptually, we have this *weird* asymmetric cryptographic authenticator construction.

## API Specification

Here, we go over the main function that are exposed by this module, i.e., `encrypt()` and `decrypt()`.

>### encrypt(senderECKeyPairPEM, receiverECPublicKeyDER, message)
- #### **senderECKeyPairPEM**: An object with properties `publicKey` and `privateKey` wrapping an asymmetric EC key pair. The keys are assumed to be in PEM format.
- #### **receiverECPublicKeyDER**: The EC public key of the receiver in DER format.
- #### **message**: Evidently, the message that we want to encrypt as a **string** type (lol, JS and types).
- #### **Returns**:  An encrypted envelope object (described below)

The encrypted envelope object returned by this function has the following structure:

```json
{
  "to": "BCbGVTb58BD04qf0NCGc8O725XCcWYk5R1KFGNkLD7laSOwmJ7VLZZdp2/Yz0R0YYTt6Gc0g9Ta80dxhShQO5N4=",
  "r": "BO1ZaCBMEF8Zs86nwRXnXQ78yVfD46WnpWcCfTHrrSscNczfQzP+6wxleJEJUliNYYlj3b4rTIOMYiuTxrDlyqc=",
  "ct": "wnVwB8EmZOBUejTolTC6bixGnxDrkFgE+Yu7fG+SYbfaxwKGANZ2GfQQ9qgNyqVPKnpuPi+9TO+Fr6+6u5h7j+AqlJCAmXDY33CPR0EMn5YSUV9W4Qr/lJuBFo3zlhCrajB7m5mvG/w5Cat3tHWaCEnh2us5o7JUvEGovkk37t8mnJZIrNGtbHoqQbkGvaxsF++zdkWiG+Xmjq25CBjVK1ICP0VFbXnFFWWsy19olH/0NXTgiCMCPxm+jyI6fIR653pUprfRVV/l4OIB7qo51qGMLkkcxVGhA/pH+oJuO1s=",
  "tag": "qI0DFJ4Q4DUWWNPDyyjX8WAxQKoFxPodu72yf+r/LHE=",
  "sig": "MEYCIQDdyRG/7qrnv7KXVRDtzRn6+6S80oySCimOD0rSzx0U6AIhAJByrXuo6wvUTeY41B0hflYpQ5eEAxhXPHrN0mkB+fOU"
}
```
A descriptive overview of the fields of an encrypted envelope object (assuming the default configuration options) is as follows:
1. `to`: The public key of the receiver in `base64` encoding.
1. `r`: A `base64` encoded crypto value related to ECDH, I won"t explain this.
1. `ct`: The ciphertext in `base64` encoding.
1. `tag`: The output of the KMAC function in `base64` encoding.
1. `sig`: The sender's signature, which was previously described.

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
The `from` field contains the PEM encoded public key of the sender. The `message` field is self-explanatory (hopefully).

The astute reader will notice that the public key of the receiver in the encrypted envelope is essentially transmitted in plaintext form. Hence, one may wonder: What if a MITM modifies it? The short answer is that in such cases, the decryption function on the receiver's end will simply fail. The main reason that we included the receiver's public key is to "help" the receiver in locating the corresponding private key. Obviously, if the receiver searches his w/e key database and does not find the respective private key, he can throw away the message even prior to calling the `decrypt()` function. However, even in the case that the developer implementing the code of the receiver is an idiot and just blindly calls the decryption function, an error will be thrown when the receiver does ECDH stuff. So, all is good my dudes.


## Configuration

***Describe the configuration options of this module following Sinica's feedback.***

## Benchmark

A "benchmark" for this implementation is provided in the `bench/bench-eciesds.js` file. You can tune the number and size of messages by modifying the `msgNo` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
ECIESDS Benchmark Inputs: 5000 messages, message_size = 100 bytes
Encryption benchmark results: total_time = 14.069853013 (secs), throughput = 355.36973949764746 (ops/sec), Avg_Op_Time = 0.0028139706025999997 (secs)
Decryption benchmark results: total_time = 13.747416197 (secs), throughput = 363.70470845940594 (ops/sec), Avg_Op_Time = 0.0027494832394 (secs)
```
for `msgNo=5000` and `msgSize=100` in my crappy VM. I assume that the output is self-explanatory.

# ECIES **DO NOT USE THIS RIGHT NOW**
In case you missed the big bold headline above, allow me to reiterate.

<span style="font-size:4em;">**DO NOT USE THE ECIES MODULE**</span>

