# Introduction

In this document, we describe our unfortunate experiences while dealing with JavaScript's official `crypto` module. We provide several examples that showcase several falacies of this API regarding a variety of topics, such as: 1) improper and misleading documentation, 2) several incosistencies regarding representations of keys as objects that are input to various functions, 3) inability to handle standardized key encodings (e.g., DER) and, 4) cases in which the API throws error messages that, from a mathematical or theoretical cryptography point of view, are invalid and, perhaps more importantly, completely misleading for, e.g., developers, that do not have solid theoretical knowledge of elliptic curve cryptography (ECC).

# JWK Support (or lack of thereof)
The [official documentation](https://nodejs.org/api/crypto.html#crypto_keyobject_export_options) states that `jwk` is a supported format for exporting keys. At the time of this writing (April 4th, 2021), the following code sample:
```js
const crypto = require('crypto')
const curveName = 'secp256k1'

let aliceECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName,
        privateKeyEncoding : {
            type: 'sec1',
            format: 'jwk'
        },
        publicKeyEncoding : {
            type: 'spki',
            format: 'pem'
        }
    }
)
```
throws the following error:
```js
node:internal/crypto/keys:208
  throw new ERR_INVALID_ARG_VALUE(optionName, formatStr);
  ^

TypeError [ERR_INVALID_ARG_VALUE]: The property 'options.publicKeyEncoding.format' is invalid. Received 'jwk'
```
We stress that the same error is thrown even if one removes the `type` propety of a key's encoding options and that the same error is thrown even if one specifies a `jwk` format for public keys.

# EC Key Pair for ECDH: Example 1
Consider the following example in which we initially create Alice's EC key pair and want to use that later on as a basis for ECDH:

```js
const crypto = require('crypto')
const curveName = 'secp256k1'

let aliceECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
let ecdh = crypto.createECDH(curveName)
ecdh.setPrivateKey(aliceECKeyPair.privateKey)
```
As you can see, we do not specify the output encoding of th EC key pair, which means that they are returned as `KeyObject` types. Running this code sample produces the following error:

```js
node:internal/crypto/util:128
    throw new ERR_INVALID_ARG_TYPE(
    ^

TypeError [ERR_INVALID_ARG_TYPE]: The "key" argument must be of type string or an instance of ArrayBuffer, Buffer, TypedArray, or DataView. Received an instance of PrivateKeyObject
```
This begs the following questions: Why does a function of the `crypto` API not support its built-in `KeyObject` type for representing keys? Why design and implement a wrapper object for cryptographic keys if it can't be used for your API's exposed functions?

# EC Key Pair for ECDH: Example 2
The error message that was thrown in the previous example clearly states that there is a problem with the format of the input key. Thus, let's export the key in a standardized format (PEM):
```js
const crypto = require('crypto')
const curveName = 'secp256k1'

let aliceECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName,
        privateKeyEncoding : {
            type: 'sec1',
            format: 'pem'
        }
    }
)
let ecdh = crypto.createECDH(curveName)
ecdh.setPrivateKey(aliceECKeyPair.privateKey)
```
Running this code sample will produce the following error:

```js
node:internal/crypto/diffiehellman:232
  this[kHandle].setPrivateKey(key);
                ^

RangeError: Private key is not valid for specified curve.
```
We stress that the same error message will be produced even if one specifies `der` as the private key's encoding format. This example showcases two significant issues:
1. The inability of the API to handle de-facto standards (PEM, DER) for encoding keys
1. Wrong and misleading error messages.

We note that we were left speechless when we came across this error message.

# EC Key Pair for ECDH: Example 3
As an alternative, one could attempt to follow the `string` type route, i.e.:
```js
const crypto = require('crypto')
const curveName = 'secp256k1'

let aliceECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
let ecdh = crypto.createECDH(curveName)
ecdh.setPrivateKey(aliceECKeyPair.privateKey.toString())
```
Surprisingly, this code sample works. One would expect that standardized formats (previous example) would come first in the priority list, however, it seems that the developers favor their own API's informal `toString()` method.

# EC Key Pair for ECDH: Example 4
Based on our findings up to this point, one might assume that using the `toString()` method of KeyObjects as input to ECDH functions is the way to go. Let's use this finding and perform the next step of ECDH, i.e., computing a shared secret between Alice and Bob:
Let's expand a little bit more on the ECDH-based example. 
```js
const crypto = require('crypto')
const curveName = 'secp256k1'

let aliceECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)

let bobECKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)

let ecdh = crypto.createECDH(curveName)
ecdh.setPrivateKey(aliceECKeyPair.privateKey.toString())
ecdh.computeSecret(bobECKeyPair.publicKey.toString())
```
This code sample produces the following error message:
```js
node:internal/crypto/diffiehellman:172
    throw new ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY();
    ^

Error [ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY]: Public key is not valid for specified curve
```
Again, we are faced with the same incosistency and misinformation by the API's error message.

**More examples to come**
