'use strict';

const mycrypto = require('../crypto')

function getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope) {
    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    return Buffer.from(encEnvelope.to_ecdh, mycrypto.encodingFormat)
}

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["to_ecdh", "r", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === undefined) {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

module.exports = {
    getDecodedECDHPublicKeyFromEncEnvelope,
    checkEncryptedEnvelopeMandatoryProperties
}