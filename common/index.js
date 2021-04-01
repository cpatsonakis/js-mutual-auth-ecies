'use strict';

const mycrypto = require('../crypto')

// Prevent benign malleability
module.exports.computeKDFInput = function(ephemeralPublicKey, sharedSecret) {
    return Buffer.concat([ephemeralPublicKey, sharedSecret],
        ephemeralPublicKey.length + sharedSecret.length)
}

module.exports.computeSymmetricEncAndMACKeys = function(kdfInput) {
    let kdfKey = mycrypto.KDF(kdfInput, mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    const symmetricEncryptionKey = kdfKey.slice(0, mycrypto.params.symmetricCipherKeySize);
    const macKey = kdfKey.slice(mycrypto.params.symmetricCipherKeySize)
    return {
        symmetricEncryptionKey,
        macKey
    };
}
