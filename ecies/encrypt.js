'use strict';

const mycrypto = require('../crypto')
const common = require('../common')

module.exports.encrypt = function(receiverECPublicKey, message) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    const ephemeralPublicKey = mycrypto.ECEphemeralKeyAgreement.generateEphemeralPublicKey()
    const sharedSecret = mycrypto.ECEphemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))

    return {
        to: receiverECPublicKey.toString(mycrypto.encodingFormat),
        r: ephemeralPublicKey.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}