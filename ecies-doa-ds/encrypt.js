'use strict';

const mycrypto = require('../crypto')
const common = require('../common')

function senderMessageWrapAndSerialization(senderPublicKey, message) {
    return JSON.stringify({
        from: senderPublicKey.toString(mycrypto.encodingFormat),
        msg: message
    });
}

module.exports.encrypt = function(senderECKeyPairPEM, receiverECPublicKey, message) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECKeyPairPEM.publicKey, message)

    const ephemeralPublicKey = mycrypto.ECEphemeralKeyAgreement.generateEphemeralPublicKey()
    const sharedSecret = mycrypto.ECEphemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey, Buffer.concat([ciphertext, iv], ciphertext.length + iv.length))

    const signature = mycrypto.computeDigitalSignature(senderECKeyPairPEM.privateKey,
        Buffer.concat([tag, sharedSecret], tag.length + sharedSecret.length))

    return {
        to: receiverECPublicKey.toString(mycrypto.encodingFormat),
        r: ephemeralPublicKey.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat),
        sig: signature.toString(mycrypto.encodingFormat)
    }
};