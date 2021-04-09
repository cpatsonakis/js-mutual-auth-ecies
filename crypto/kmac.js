'use strict';

const crypto = require('crypto');
const config = require('./private_config');

function computeKMAC(key, data) {
    if (key.length != config.macKeySize) {
        throw new Error('Invalid length of input MAC key')
    }
    return crypto.createHmac(config.hashFunctionName, key).update(data).digest();
}

function verifyKMAC(tag, key, data) {
    if (key.length != config.macKeySize) {
        throw new Error('Invalid length of input MAC key')
    }
    const timingSafeEqual = require('./index').timingSafeEqual;
    const computedTag = computeKMAC(key, data)
    return timingSafeEqual(computedTag, tag)
}

module.exports = {
    computeKMAC,
    verifyKMAC
}