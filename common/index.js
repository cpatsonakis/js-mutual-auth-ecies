'use strict';

const mycrypto = require('../crypto')

// Prevent benign malleability
function computeKDFInput(ephemeralPublicKey, sharedSecret) {
    return Buffer.concat([ephemeralPublicKey, sharedSecret],
        ephemeralPublicKey.length + sharedSecret.length)
}

function computeSymmetricEncAndMACKeys(kdfInput) {
    let kdfKey = mycrypto.KDF(kdfInput, mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    const symmetricEncryptionKey = kdfKey.slice(0, mycrypto.params.symmetricCipherKeySize);
    const macKey = kdfKey.slice(mycrypto.params.symmetricCipherKeySize)
    return {
        symmetricEncryptionKey,
        macKey
    };
}

function getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope) {
    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    return Buffer.from(encEnvelope.to_ecdh, mycrypto.encodingFormat)
}

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["to_ecdh", "r", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

function createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralECDHPublicKey, ciphertext, iv, tag) {
    return {
        to_ecdh: receiverECDHPublicKey.toString(mycrypto.encodingFormat),
        r: ephemeralECDHPublicKey.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}

function checkKeyPairMandatoryProperties(keyPairObject) {
    const mandatoryProperties = ["publicKey", "privateKey"];
    mandatoryProperties.forEach((property) => {
        if (typeof keyPairObject[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input key pair object");
        }
    })
}

module.exports = {
    computeKDFInput,
    computeSymmetricEncAndMACKeys,
    getDecodedECDHPublicKeyFromEncEnvelope,
    checkEncryptedEnvelopeMandatoryProperties,
    createEncryptedEnvelopeObject,
    checkKeyPairMandatoryProperties
}