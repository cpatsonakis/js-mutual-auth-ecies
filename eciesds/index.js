/*
In this version of the protocol, we use digital signatures instead of a MAC-based authenticator
to authenticate the sender of the message to the receiver. As in the previous implementation, the
sender of the message is hidden while in transit.
*/
'use strict'; // yes, yes... JS is a very "strict" language...

const crypto = require('crypto');

let config = {
  cryptoOptions: {
    kdfName: 'sha3-256',
    macName: 'sha3-256',
    curveName: 'secp256k1',
    signHashFunction: 'sha3-256',
    symmetricCipherName: 'aes-128-ecb',
    symmetricCipherKeySize: 16,
    keyFormat: 'uncompressed',
    securityLevelBytes: 16
  },
  encodingFormat: 'base64',
  symmetricEncrypt: symmetricEncrypt,
  symmetricDecrypt: symmetricDecrypt,
  computeKeyedMAC: computeKeyedMAC,
  verifyKeyedMAC: verifyKeyedMAC,
  computeDigitalSignature: computeDigitalSignature,
  verifyDigitalSignature: verifyDigitalSignature,
  senderComputeECDHValues: senderComputeECDHValues,
  receiverComputeECDHSharedSecret: receiverComputeECDHSharedSecret
};

function symmetricEncrypt(key, plaintext) {
  if (key.length < config.cryptoOptions.securityLevelBytes) {
    throw new Error('Symmetric encryption key does not correspond to configured security level')
  }
  let cipher = crypto.createCipheriv(config.cryptoOptions.symmetricCipherName, key, null);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function symmetricDecrypt(key, ciphertext) {
  if (key.length < config.cryptoOptions.securityLevelBytes) {
    throw new Error('Symmetric decryption key does not correspond to configured security level')
  }
  let cipher = crypto.createDecipheriv(config.cryptoOptions.symmetricCipherName, key, null);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Keyed MAC function
function computeKeyedMAC(key, message) {
  return crypto.createHmac(config.cryptoOptions.macName, key).update(message).digest();
}

function evaluateKDF(secretValue) {
  return crypto.createHash(config.cryptoOptions.kdfName).update(secretValue).digest()
}

function computeSymmetricEncAndMACKeysFromSecret(secretValue) {
  let kdfKey = evaluateKDF(secretValue)
  if (kdfKey.length < 2 * config.cryptoOptions.securityLevelBytes) {
    throw new Error("KDF output is not big enough for configured security level")
  }
  const symmetricEncryptionKey = kdfKey.slice(0, config.cryptoOptions.symmetricCipherKeySize);
  const macKey = kdfKey.slice(config.cryptoOptions.symmetricCipherKeySize)
  return {
    symmetricEncryptionKey,
    macKey
  };
}

function computeDigitalSignature(privateKeyPEM, buffer) {
  let signObject = crypto.createSign(config.cryptoOptions.signHashFunction)
  signObject.update(buffer)
  signObject.end();
  return signObject.sign(privateKeyPEM, config.encodingFormat)

}
function senderComputeECDHValues(receiverPublicKeyDER) {
  let senderECDH = crypto.createECDH(config.cryptoOptions.curveName)
  let R = senderECDH.generateKeys()
  let sharedSecret = senderECDH.computeSecret(receiverPublicKeyDER)
  return {
    R,
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

  const {R, sharedSecret} = senderComputeECDHValues(receiverECPublicKeyDER)

  const {symmetricEncryptionKey, macKey} = computeSymmetricEncAndMACKeysFromSecret(sharedSecret)

  const ciphertext = config.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized)
  const tag = config.computeKeyedMAC(macKey, ciphertext)

  const signature = config.computeDigitalSignature(senderECKeyPairPEM.privateKey, 
    Buffer.concat([tag, sharedSecret], tag.length + sharedSecret.length))

  return {
    to: receiverECPublicKeyDER.toString(config.encodingFormat),
    r: R.toString(config.encodingFormat),
    ct: ciphertext.toString(config.encodingFormat),
    tag: tag.toString(config.encodingFormat),
    sig: signature
  }
};

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
  const mandatoryProperties = ["to", "r", "ct", "tag", "sig"];
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

function receiverComputeECDHSharedSecret(receiverPrivateKeyDER, envelope) {
  const ephemeralReceiverECDH = crypto.createECDH(config.cryptoOptions.curveName);
  ephemeralReceiverECDH.setPrivateKey(receiverPrivateKeyDER)
  if (!equalConstTime(ephemeralReceiverECDH.getPublicKey().toString(config.encodingFormat), envelope.to)) {
    throw new Error("Computed ECDH public key does not match the one encoded in the envelope")
  }
  return ephemeralReceiverECDH.computeSecret(Buffer.from(envelope.r, config.encodingFormat));
}

function verifyKeyedMAC(tag, key, message) {
  const computedTag = config.computeKeyedMAC(key, message)
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
  let verifyObject = crypto.createVerify(config.cryptoOptions.signHashFunction)
  verifyObject.update(buffer)
  verifyObject.end()
  if (!verifyObject.verify(publicKeyPEM, signature)) {
    throw new Error("Bad signature")
  }
}

function decrypt(receiverPrivateKeyDER, encEnvelope) {

  checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

  const sharedSecret = config.receiverComputeECDHSharedSecret(receiverPrivateKeyDER, encEnvelope)

  const {symmetricEncryptionKey, macKey} = computeSymmetricEncAndMACKeysFromSecret(sharedSecret)

  const ciphertext = Buffer.from(encEnvelope.ct, config.encodingFormat)
  const tag = Buffer.from(encEnvelope.tag, config.encodingFormat)

  verifyKeyedMAC(tag, macKey, ciphertext)

  let wrappedMessageObject = JSON.parse(config.symmetricDecrypt(symmetricEncryptionKey, ciphertext).toString())
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