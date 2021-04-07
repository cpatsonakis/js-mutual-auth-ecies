'use strict';

const mycrypto = require('../crypto')
const common = require('../common')


function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["to", "r", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === undefined) {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

module.exports.decrypt = function (receiverPrivateKey, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ephemeralPublicKey = Buffer.from(encEnvelope.r, mycrypto.encodingFormat)

    const sharedSecret = mycrypto.ECEphemeralKeyAgreement.computeSharedSecretFromKeyPair(receiverPrivateKey, ephemeralPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)

    mycrypto.KMAC.verifyKMAC(tag, macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))


    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}