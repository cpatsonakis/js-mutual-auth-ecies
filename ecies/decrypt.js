'use strict';

const mycrypto = require('../crypto')
const common = require('../common')


module.exports.decrypt = function (receiverECDHPrivateKey, encEnvelope) {

    common.checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ephemeralPublicKey = mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(encEnvelope.r)

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
    const sharedSecret = ephemeralKeyAgreement.computeSharedSecretFromKeyPair(receiverECDHPrivateKey, ephemeralPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length))
    ) {
        throw new Error("Bad MAC")
    }

    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}