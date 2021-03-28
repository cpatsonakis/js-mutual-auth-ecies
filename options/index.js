'use strict'

// default options 
module.exports = {
    kdfName: 'sha3-256',
    kdfLength: 32,
    macName: 'sha3-256',
    macLength: 32,
    curveName: 'secp256k1',
    symmetricCipherName: 'aes-128-ecb',
    symmetricCipherKeySize: 16,
    keyFormat: 'uncompressed',
    encodingFormat: 'base64'
};