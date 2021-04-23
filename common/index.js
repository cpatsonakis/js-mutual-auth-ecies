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
    if (encEnvelope.to_ecdh === undefined) {
        throw new Error("Receiver ECDH public key property not found in input encrypted envelope")
    }
    return mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(encEnvelope.to_ecdh)
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
        to_ecdh: mycrypto.PublicKeySerializer.serializeECDHPublicKey(receiverECDHPublicKey),
        r: mycrypto.PublicKeySerializer.serializeECDHPublicKey(ephemeralECDHPublicKey),
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