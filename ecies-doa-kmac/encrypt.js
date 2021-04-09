'use strict';

const mycrypto = require('../crypto');
const common = require('../common')

function senderMessageWrapAndSerialization(senderECDHPublicKey, message) {
  return JSON.stringify({
    from_ecdh: senderECDHPublicKey.toString(mycrypto.encodingFormat),
    msg: message
  });
}

module.exports.encrypt = function (senderECDHKeyPair, receiverECDHPublicKey, message) {

  if (!Buffer.isBuffer(message)) {
    throw new Error('Input message has to be of type Buffer')
  }

  const senderKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
  const senderDerivedSharedSecret = senderKeyAgreement.computeSharedSecretFromKeyPair(senderECDHKeyPair.privateKey, receiverECDHPublicKey)

  const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECDHKeyPair.publicKey, message);

  const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
  const ephemeralPublicKey = ephemeralKeyAgreement.generateEphemeralPublicKey()
  const ephemeralSharedSecret = ephemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECDHPublicKey)

  const kdfInput = common.computeKDFInput(ephemeralPublicKey, ephemeralSharedSecret)
  const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

  const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
  const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv)
  const tag = mycrypto.KMAC.computeKMAC(macKey,
    Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
      ciphertext.length + iv.length + senderDerivedSharedSecret.length)
  )

  return {
    to_ecdh: receiverECDHPublicKey.toString(mycrypto.encodingFormat),
    r: ephemeralPublicKey.toString(mycrypto.encodingFormat),
    ct: ciphertext.toString(mycrypto.encodingFormat),
    iv: iv.toString(mycrypto.encodingFormat),
    tag: tag.toString(mycrypto.encodingFormat)
  }
};
