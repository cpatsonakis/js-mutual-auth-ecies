'use strict';

const crypto = require('crypto');
const config = require('./private_config')


function symmetricEncrypt(key, plaintext, iv) {
    if (key.length != config.symmetricCipherKeySize) {
        throw new Error('Invalid length of input symmetric encryption key')
    }
    if (iv === undefined) {
        iv = null
    }
    let cipher = crypto.createCipheriv(config.symmetricCipherName, key, iv);
    const firstChunk = cipher.update(plaintext);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

function symmetricDecrypt(key, ciphertext, iv) {
    if (key.length != config.symmetricCipherKeySize) {
        throw new Error('Invalid length of input symmetric decryption key')
    }
    if (iv === undefined) {
        iv = null
    }
    let cipher = crypto.createDecipheriv(config.symmetricCipherName, key, iv);
    const firstChunk = cipher.update(ciphertext);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

module.exports = {
    symmetricEncrypt,
    symmetricDecrypt
}