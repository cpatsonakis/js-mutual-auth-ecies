'use strict';

const crypto = require('crypto');
const config = require('./config')


function symmetricEncrypt(key, plaintext, iv) {
    if (key.length < config.symmetricCipherKeySize) {
        throw new Error('Symmetric encryption key does not correspond to configured security level')
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
    if (key.length < config.symmetricCipherKeySize) {
        throw new Error('Symmetric decryption key does not correspond to configured security level')
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