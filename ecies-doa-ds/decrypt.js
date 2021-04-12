'use strict';

const mycrypto = require('../crypto')
const common = require('../common')
const crypto = require('crypto')

function checkWrappedMessageMandatoryProperties(wrappedMessage) {
    const mandatoryProperties = ["from_ecsig", "msg", "sig"];
    mandatoryProperties.forEach((property) => {
        if (typeof wrappedMessage[property] === undefined) {
            throw new Error("Mandatory property " + property + " is missing from wrapped message");
        }
    })
}

module.exports.decrypt = function (receiverECDHPrivateKey, encEnvelope) {

    common.checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ephemeralPublicKey = Buffer.from(encEnvelope.r, mycrypto.encodingFormat)

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

    let wrappedMessageObject = JSON.parse(mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv).toString())
    checkWrappedMessageMandatoryProperties(wrappedMessageObject)
    const senderECSigVerPublicKey = crypto.createPublicKey({
        key: wrappedMessageObject.from_ecsig,
        format: 'pem',
        type: 'spki'
    })

    if (!mycrypto.verifyDigitalSignature(senderECSigVerPublicKey,
        Buffer.from(wrappedMessageObject.sig, mycrypto.encodingFormat),
        sharedSecret)) {
        throw new Error("Bad signature")
    }
    return {
        from_ecsig: senderECSigVerPublicKey,
        message: Buffer.from(wrappedMessageObject.msg, mycrypto.encodingFormat)
    };
}
