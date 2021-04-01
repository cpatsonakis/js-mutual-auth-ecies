'use strict';

const cipher = require('./cipher')
const kdf = require('./kdf')
const kmac = require('./kmac')
const config = require('./config')
const sig = require('./digitalsig')
const crypto = require('crypto')
const ecephka = require('./ecephka')

module.exports = {
    encodingFormat: 'base64',
    getRandomBytes: crypto.randomBytes,
    computeDigitalSignature: sig.computeDigitalSignature,
    verifyDigitalSignature: sig.verifyDigitalSignature,
    symmetricEncrypt: cipher.symmetricEncrypt,
    symmetricDecrypt: cipher.symmetricDecrypt,
    KMAC: kmac,
    ECEphemeralKeyAgreement: ecephka,
    KDF: kdf.KDF2,
    params: {
        symmetricCipherKeySize: config.symmetricCipherKeySize,
        macKeySize: config.macKeySize,
        ivSize: config.ivSize,
    }
}