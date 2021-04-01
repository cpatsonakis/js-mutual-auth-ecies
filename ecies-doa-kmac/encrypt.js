'use strict';

const mycrypto = require('../crypto');
const common = require('../common')

function senderMessageWrapAndSerialization(senderPublicKey, message) {
  return JSON.stringify({
    from: senderPublicKey.toString(mycrypto.encodingFormat),
    msg: message
  });
}

module.exports.encrypt = function (senderKeyPair, receiverPublicKey, message) {

  const senderDerivedSharedSecret = mycrypto.ECEphemeralKeyAgreement.computeSharedSecretFromKeyPair(senderKeyPair.privateKey, receiverPublicKey)

  const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderKeyPair.publicKey, message);

  const ephemeralPublicKey = mycrypto.ECEphemeralKeyAgreement.generateEphemeralPublicKey()
  const ephemeralSharedSecret = mycrypto.ECEphemeralKeyAgreement.generateSharedSecretForPublicKey(receiverPublicKey)

  const kdfInput = common.computeKDFInput(ephemeralPublicKey, ephemeralSharedSecret)
  const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

  const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
  const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv)
  const tag = mycrypto.KMAC.computeKMAC(macKey,
    Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
      ciphertext.length + iv.length + senderDerivedSharedSecret.length)
  )

  return {
    to: receiverPublicKey.toString(mycrypto.encodingFormat),
    r: ephemeralPublicKey.toString(mycrypto.encodingFormat),
    ct: ciphertext.toString(mycrypto.encodingFormat),
    iv: iv.toString(mycrypto.encodingFormat),
    tag: tag.toString(mycrypto.encodingFormat)
  }
};
