'use strict';

const mycrypto = require('../crypto')
const common = require('../common')

module.exports.encrypt = function (receiverECDHPublicKey, message) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
    const ephemeralPublicKey = ephemeralKeyAgreement.generateEphemeralPublicKey()
    const sharedSecret = ephemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECDHPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length)
    )

    return common.createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralPublicKey, ciphertext, iv, tag)
}