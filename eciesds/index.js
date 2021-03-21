/*
In this version of the protocol, we use digital signatures instead of a MAC-based authenticator
to authenticate the sender of the message to the receiver. As in the previous implementation, the
sender of the message is hidden while in transit.
*/
'use strict'; // yes, yes... JS is a very "strict" language...

const crypto = require('crypto');
const assert = require('assert');
const options = require('../options');

// Symmetric decryption based on the input key. This function assumes
// that we are using a symmetric cipher that does not require an IV
function symmetricEncrypt(cypherName, key, plaintext) {
  let cipher = crypto.createCipheriv(cypherName, key, null);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Symmetric decryption based on the input key. This function assumes
// that we are using a symmetric cipher that does not require an IV
function symmetricDecrypt(cypherName, key, ciphertext) {
  let cipher = crypto.createDecipheriv(cypherName, key, null);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Key MAC function
function macMessage(cypherName, key, message) {
  return crypto.createHmac(cypherName, key).update(message).digest();
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

exports.encrypt = function (senderECKeyPair, receiverECDHPublicKey, message) {

  var messageEncoded = message.toString('base64url')

  var senderAuthMsgEnvelope = {
    from: senderECKeyPair.publicKey,
    msg: messageEncoded
  }

  const senderAuthMsgEnvelopeSerialized = JSON.stringify(senderAuthMsgEnvelope)

  // Ok, now we are going to compute the ephemeral DH secret based on the public key of the
  // receiver
  var ephemeralSenderECDH = crypto.createECDH(options.curveName)
  const R = ephemeralSenderECDH.generateKeys()

  // Ephemeral Shared Secret
  const ephemeralSharedSecret = ephemeralSenderECDH.computeSecret(receiverECDHPublicKey);

  // Derive the ephemeral encryption key (ephEncKey) and the ephemeral MAC key (ephMACKey)
  // ephEncKey || epcMACKey = KDF(ephemeralSharedSecret)
  const ephemeralKDF = crypto.createHash(options.kdfName).update(ephemeralSharedSecret).digest()

  // Yes yes... we fucking assume that the length of the hash function is divisible by 2
  // Try and find a hash function that doesn't have a byte output with that property you retard...
  const ephemeralEncKey = ephemeralKDF.slice(0, options.kdfLength / 2);
  const ephemeralMACKey = ephemeralKDF.slice(options.kdfLength / 2);

  const serializedEnvelopeCiphertext = symmetricEncrypt(options.symmetricCypherName, ephemeralEncKey, senderAuthMsgEnvelopeSerialized);
  const serializedEnvelopeTag = macMessage(options.macName, ephemeralMACKey, serializedEnvelopeCiphertext);

  //And now we use the EC private key of the sender to sign the tag

  var senderSign = crypto.createSign(options.kdfName)
  senderSign.update(serializedEnvelopeTag)
  senderSign.end();
  const senderSignature = senderSign.sign(senderECKeyPair.privateKey, 'base64url')

  return {
    to: receiverECDHPublicKey.toString('base64url'),
    r: R.toString('base64url'),
    ct: serializedEnvelopeCiphertext.toString('base64url'),
    tag: serializedEnvelopeTag.toString('base64url'),
    sig: senderSignature
  }
};

exports.decrypt = function (receiverPrivateKey, encEnvelope) {
  // Some envelope format checks are warranted first...
  assert(('to' in encEnvelope), "eciesds::decrypt(): 'to' property not found on input encrypted envelope")
  assert(('r' in encEnvelope), "eciesds::decrypt(): 'r' property not found on input encrypted envelope")
  assert(('ct' in encEnvelope), "eciesds::decrypt(): 'ct' property not found on input encrypted envelope")
  assert(('tag' in encEnvelope), "eciesds::decrypt(): 'tag' property not found on input encrypted envelope")
  assert(('sig' in encEnvelope), "eciesds::decrypt(): 'sig' property not found on input encrypted envelope")

  const ephemeralReceiverECDH = crypto.createECDH(options.curveName);
  ephemeralReceiverECDH.setPrivateKey(receiverPrivateKey)

  assert(equalConstTime(ephemeralReceiverECDH.getPublicKey().toString('base64url'), encEnvelope.to),
    "eciesds::decrypt(): Public keys do not match")

  // Ephemeral Shared Secret
  const ephemeralSharedSecret = ephemeralReceiverECDH.computeSecret(Buffer.from(encEnvelope.r, 'base64url'));

  // Derive the ephemeral encryption key (ephEncKey) and the ephemeral MAC key (ephMACKey)
  // ephEncKey || epcMACKey = KDF(ephemeralSharedSecret)
  const ephemeralKDF = crypto.createHash(options.kdfName).update(ephemeralSharedSecret).digest()

  // Yes yes... we fucking assume that the length of the hash function is divisible by 2
  // Try and find a hash function that doesn't have a byte output with that property you retard...
  const ephemeralEncKey = ephemeralKDF.slice(0, options.kdfLength / 2);
  const ephemeralMACKey = ephemeralKDF.slice(options.kdfLength / 2);

  const ciphertextBuffer = Buffer.from(encEnvelope.ct, 'base64url')

  const serializedEnvelopeTag = macMessage(options.macName, ephemeralMACKey, ciphertextBuffer);
  assert(equalConstTime(serializedEnvelopeTag.toString('base64url'), encEnvelope.tag), "eciesds::decrypt(): Bad MAC")

  var senderAuthMsgEnvelopeSerialized = symmetricDecrypt(options.symmetricCypherName, ephemeralEncKey, ciphertextBuffer)
  var senderAuthMsgEnvelope = JSON.parse(senderAuthMsgEnvelopeSerialized.toString())

  assert(('from' in senderAuthMsgEnvelope), "eciesds::decrypt(): 'from' property not found on sender's authenticated envelope")
  assert(('msg' in senderAuthMsgEnvelope), "eciesds::decrypt(): 'msg' property not found on sender's authenticated envelope")

  const signatureBuffer = Buffer.from(encEnvelope.sig, 'base64url')
  const receiverVerify = crypto.createVerify(options.kdfName)
  receiverVerify.update(serializedEnvelopeTag)
  receiverVerify.end()
  assert(receiverVerify.verify(senderAuthMsgEnvelope.from, signatureBuffer) === true, "eciesds::decrypt() Bad signature")
  return {
      from: senderAuthMsgEnvelope.from,
      message: Buffer.from(senderAuthMsgEnvelope.msg, 'base64url')
  }
}
