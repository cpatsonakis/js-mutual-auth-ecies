'use strict'

// default options 
exports.options = {
    kdfName: 'sha3-512',
    kdfLength: 64,
    macName: 'sha256',
    macLength: 32,
    curveName: 'secp256k1',
    symmetricCypherName: 'aes-128-ecb',
    keyFormat: 'uncompressed'
};