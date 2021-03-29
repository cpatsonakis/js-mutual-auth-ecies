/*
In this version of the protocol, we use digital signatures instead of a MAC-based authenticator
to authenticate the sender of the message to the receiver. As in the previous implementation, the
sender of the message is hidden while in transit.
*/
'use strict'; // yes, yes... JS is a very "strict" language...

const crypto = require('crypto');

let config = {
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

function symmetricEncrypt(key, plaintext, iv) {
  if (key.length < config.cryptoOptions.symmetricCipherKeySize) {
    throw new Error('Symmetric encryption key does not correspond to configured security level')
  }
  if (iv === undefined) {
    iv = null
  }
  let cipher = crypto.createCipheriv(config.cryptoOptions.symmetricCipherName, key, iv);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function symmetricDecrypt(key, ciphertext, iv) {
  if (key.length < config.cryptoOptions.symmetricCipherKeySize) {
    throw new Error('Symmetric decryption key does not correspond to configured security level')
  }
  if (iv === undefined) {
    iv = null
  }
  let cipher = crypto.createDecipheriv(config.cryptoOptions.symmetricCipherName, key, iv);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Keyed MAC function
function computeKeyedMAC(key, data) {
  return crypto.createHmac(config.cryptoOptions.hashFunctionName, key).update(data).digest();
}

// Implementation of KDF2 as defined in ISO/IEC 18033-2
function KDF2(x, outputByteSize) {
  if (outputByteSize < 0) {
    throw new Error("KDF output key byte size needs to be >= 0, not " + outputByteSize)
  } //silly optimization here
  else if (outputByteSize === 0 ) {
    return Buffer.alloc(0)
  }
  let k = Math.ceil(outputByteSize/config.cryptoOptions.hashSize)
  k++;
  let derivedKeyBuffer = Buffer.alloc(outputByteSize)
  let iBuffer = Buffer.alloc(4)
  for(let i = 1 ; i < k ; i++) {
    iBuffer.writeInt32BE(i)
    let roundInput = Buffer.concat([x, iBuffer], x.length + iBuffer.length)
    let roundHash = crypto.createHash(config.cryptoOptions.hashFunctionName).update(roundInput).digest()
    roundHash.copy(derivedKeyBuffer,(i-1) * config.cryptoOptions.hashSize)
  }
  return derivedKeyBuffer
}

// Prevent benign malleability
function computeKDFInput(ephemeralPublicKey, sharedSecret) {
  return Buffer.concat([ephemeralPublicKey, sharedSecret],
    ephemeralPublicKey.length + sharedSecret.length)
}

function computeSymmetricEncAndMACKeys(kdfInput) {
  let kdfKey = config.evaluateKDF(kdfInput, config.cryptoOptions.symmetricCipherKeySize + config.cryptoOptions.macKeySize)
  const symmetricEncryptionKey = kdfKey.slice(0, config.cryptoOptions.symmetricCipherKeySize);
  const macKey = kdfKey.slice(config.cryptoOptions.symmetricCipherKeySize)
  return {
    symmetricEncryptionKey,
    macKey
  };
}

function computeDigitalSignature(privateKeyPEM, buffer) {
  let signObject = crypto.createSign(config.cryptoOptions.signHashFunctionName)
  signObject.update(buffer)
  signObject.end();
  return signObject.sign(privateKeyPEM, config.encodingFormat)

}
function senderComputeECDHValues(receiverPublicKeyDER) {
  let senderECDH = crypto.createECDH(config.cryptoOptions.curveName)
  let ephemeralPublicKey = senderECDH.generateKeys()
  let sharedSecret = senderECDH.computeSecret(receiverPublicKeyDER)
  return {
    ephemeralPublicKey,
    sharedSecret
  };
}

function senderMessageWrapAndSerialization(senderPublicKey, message) {
  return JSON.stringify({
    from: senderPublicKey.toString(config.encodingFormat),
    msg: message
  });
}

function encrypt(senderECKeyPairPEM, receiverECPublicKeyDER, message) {

  if(!((typeof message) === 'string')) {
    throw new Error('message should be in string format')
  }

  const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECKeyPairPEM.publicKey, message)

  const {ephemeralPublicKey, sharedSecret} = senderComputeECDHValues(receiverECPublicKeyDER)

  const kdfInput = computeKDFInput(ephemeralPublicKey, sharedSecret)
  const {symmetricEncryptionKey, macKey} = computeSymmetricEncAndMACKeys(kdfInput)

  const iv = config.getRandomBytes(config.cryptoOptions.ivSize)
  const ciphertext = config.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv)
  const tag = config.computeKeyedMAC(macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))

  const signature = config.computeDigitalSignature(senderECKeyPairPEM.privateKey, 
    Buffer.concat([tag, sharedSecret], tag.length + sharedSecret.length))

  return {
    to: receiverECPublicKeyDER.toString(config.encodingFormat),
    r: ephemeralPublicKey.toString(config.encodingFormat),
    ct: ciphertext.toString(config.encodingFormat),
    iv: iv.toString(config.encodingFormat),
    tag: tag.toString(config.encodingFormat),
    sig: signature
  }
};

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
  const mandatoryProperties = ["to", "r", "ct", "iv", "tag", "sig"];
  mandatoryProperties.forEach( (property) => {
    if (typeof encryptedEnvelope[property] == "undefined") {
      throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
    }
  })
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < b1.length; i++) {
    result |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return result === 0;
}

function receiverComputeECDHSharedSecret(receiverPrivateKeyDER, ephemeralPublicKey) {
  const receiverECDH = crypto.createECDH(config.cryptoOptions.curveName);
  receiverECDH.setPrivateKey(receiverPrivateKeyDER)
  return receiverECDH.computeSecret(ephemeralPublicKey);
}

function verifyKeyedMAC(tag, key, data) {
  const computedTag = config.computeKeyedMAC(key, data)
  if (!equalConstTime(computedTag, tag)) {
    throw new Error("Bad MAC")
  }
}

function checkWrappedMessageMandatoryProperties(wrappedMessage) {
  const mandatoryProperties = ["from", "msg"];
  mandatoryProperties.forEach( (property) => {
    if (typeof wrappedMessage[property] == "undefined") {
      throw new Error("Mandatory property " + property + " is missing from wrapped message");
    }
  })
}

function verifyDigitalSignature(publicKeyPEM, signature, buffer) {
  let verifyObject = crypto.createVerify(config.cryptoOptions.signHashFunctionName)
  verifyObject.update(buffer)
  verifyObject.end()
  if (!verifyObject.verify(publicKeyPEM, signature)) {
    throw new Error("Bad signature")
  }
}

function decrypt(receiverPrivateKeyDER, encEnvelope) {

  checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

  const ephemeralPublicKey = Buffer.from(encEnvelope.r, config.encodingFormat)
  const sharedSecret = config.receiverComputeECDHSharedSecret(receiverPrivateKeyDER, ephemeralPublicKey)


  const kdfInput = computeKDFInput(ephemeralPublicKey, sharedSecret)
  const {symmetricEncryptionKey, macKey} = computeSymmetricEncAndMACKeys(kdfInput)

  const ciphertext = Buffer.from(encEnvelope.ct, config.encodingFormat)
  const tag = Buffer.from(encEnvelope.tag, config.encodingFormat)
  const iv = Buffer.from(encEnvelope.iv, config.encodingFormat)

  verifyKeyedMAC(tag, macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))

  let wrappedMessageObject = JSON.parse(config.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv).toString())
  checkWrappedMessageMandatoryProperties(wrappedMessageObject)

  config.verifyDigitalSignature(wrappedMessageObject.from,
    Buffer.from(encEnvelope.sig, config.encodingFormat),
    Buffer.concat([tag, sharedSecret], tag.length + sharedSecret.length))
  return {
    from: wrappedMessageObject.from,
    message: wrappedMessageObject.msg
  };
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  config: config
}