'use strict';

const mycrypto = require('../crypto')
const common = require('../common')
const utils = require('./utils')


module.exports.decrypt = function (receiverPrivateKey, encEnvelope) {

    utils.checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ephemeralPublicKey = Buffer.from(encEnvelope.r, mycrypto.encodingFormat)

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
    const sharedSecret = ephemeralKeyAgreement.computeSharedSecretFromKeyPair(receiverPrivateKey, ephemeralPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)

    mycrypto.KMAC.verifyKMAC(tag, macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))


    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}