'use strict';

const mycrypto = require('../crypto')
const common = require('../common');

function senderMessageWrapAndSerialization(senderECSigVerPublicKey, message, signature) {
    return JSON.stringify({
        from_ecsig: senderECSigVerPublicKey.export({
            type: 'spki',
            format: 'pem'
        }),
        msg: message.toString(mycrypto.encodingFormat),
        sig: signature.toString(mycrypto.encodingFormat)
    });
}

module.exports.encrypt = function (senderECSigningKeyPair, receiverECDHPublicKey, message) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
    const ephemeralPublicKey = ephemeralKeyAgreement.generateEphemeralPublicKey()
    const sharedSecret = ephemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECDHPublicKey)

    const signature = mycrypto.computeDigitalSignature(senderECSigningKeyPair.privateKey, sharedSecret)
    const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECSigningKeyPair.publicKey, message, signature)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput)

    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length)
    )

    return common.createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralPublicKey, ciphertext, iv, tag)
};