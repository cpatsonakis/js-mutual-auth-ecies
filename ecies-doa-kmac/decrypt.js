'use strict';

const mycrypto = require('../crypto');
const common = require('../common')

function checkWrappedMessageMandatoryProperties(wrappedMessage) {
    const mandatoryProperties = ["from_ecdh", "msg"];
    mandatoryProperties.forEach((property) => {
        if (typeof wrappedMessage[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from wrapped message");
        }
    })
}

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

    const wrappedMessageObject = JSON.parse(mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv).toString())
    checkWrappedMessageMandatoryProperties(wrappedMessageObject)
    const senderPublicKey = mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(wrappedMessageObject.from_ecdh)

    const senderKeyAgreement = new mycrypto.ECEphemeralKeyAgreement()
    const senderDerivedSharedSecret = senderKeyAgreement.computeSharedSecretFromKeyPair(receiverECDHPrivateKey, senderPublicKey)
    // **TODO**: This does not seem correct, need to think about it.
    mycrypto.KMAC.verifyKMAC(tag, macKey,
        Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
            ciphertext.length + iv.length + senderDerivedSharedSecret.length)
    )

    return {
        from_ecdh: senderPublicKey,
        message: Buffer.from(wrappedMessageObject.msg, mycrypto.encodingFormat)
    };
}