'use strict';

const mycrypto = require('../crypto');
const common = require('../common')

function senderMessageWrapAndSerialization(senderECDHPublicKey, message) {
  return JSON.stringify({
    from_ecdh: mycrypto.PublicKeySerializer.serializeECDHPublicKey(senderECDHPublicKey),
    msg: message
  });
}

module.exports.encrypt = function (senderECDHKeyPair, receiverECDHPublicKey, message) {

  if (!Buffer.isBuffer(message)) {
    throw new Error('Input message has to be of type Buffer')
  }

  common.checkKeyPairMandatoryProperties(senderECDHKeyPair)

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
  // **TODO**: This does not seem correct, need to think about it.
  const tag = mycrypto.KMAC.computeKMAC(macKey,
    Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
      ciphertext.length + iv.length + senderDerivedSharedSecret.length)
  )

  return common.createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralPublicKey, ciphertext, iv, tag)
};
