'use strict';

const crypto = require('crypto');
const config = require('./config')

function computeDigitalSignature(privateKeyPEM, buffer) {
    let signObject = crypto.createSign(config.signAlgoName)
    signObject.update(buffer)
    signObject.end();
    return signObject.sign(privateKeyPEM, config.encodingFormat)

}

function verifyDigitalSignature(publicKeyPEM, signature, buffer) {
    let verifyObject = crypto.createVerify(config.signAlgoName)
    verifyObject.update(buffer)
    verifyObject.end()
    return verifyObject.verify(publicKeyPEM, signature)
}

module.exports = {
    computeDigitalSignature,
    verifyDigitalSignature
}