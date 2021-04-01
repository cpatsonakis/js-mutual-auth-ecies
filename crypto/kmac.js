'use strict';

const crypto = require('crypto');
const config = require('./config')
const helpers = require('./helpers')

function computeKMAC(key, data) {
    return crypto.createHmac(config.hashFunctionName, key).update(data).digest();
}

function verifyKMAC(tag, key, data) {
    const computedTag = computeKMAC(key, data)
    return helpers.equalConstTime(computedTag, tag)
}

module.exports = {
    computeKMAC,
    verifyKMAC
}