'use strict';

const crypto = require('crypto');
const config = require('./private_config');

function computeDigitalSignature(privateECSigningKey, buffer) {
    let encodingFormat = require('./index').encodingFormat;
    let signObject = crypto.createSign(config.signAlgoName)
    signObject.update(buffer)
    signObject.end();
    return signObject.sign(privateECSigningKey, encodingFormat)

}

function verifyDigitalSignature(publicECVerificationKey, signature, buffer) {
    let verifyObject = crypto.createVerify(config.signAlgoName)
    verifyObject.update(buffer)
    verifyObject.end()
    return verifyObject.verify(publicECVerificationKey, signature)
}

module.exports = {
    computeDigitalSignature,
    verifyDigitalSignature
}