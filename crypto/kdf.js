'use strict';

const crypto = require('crypto');
const config = require('./private_config')

// Implementation of KDF2 as defined in ISO/IEC 18033-2
function KDF2(x, outputByteSize, hashFunction = config.hashFunctionName, hashSize = config.hashSize) {
    if (outputByteSize < 0) {
        throw new Error("KDF output key byte size needs to be >= 0, not " + outputByteSize)
    } //silly optimization here
    else if (outputByteSize === 0) {
        return Buffer.alloc(0)
    }
    let k = Math.ceil(outputByteSize / hashSize)
    k++;
    let derivedKeyBuffer = Buffer.alloc(outputByteSize)
    let iBuffer = Buffer.alloc(4)
    for (let i = 1; i < k; i++) {
        iBuffer.writeInt32BE(i)
        let roundInput = Buffer.concat([x, iBuffer], x.length + iBuffer.length)
        let roundHash = crypto.createHash(hashFunction).update(roundInput).digest()
        roundHash.copy(derivedKeyBuffer, (i - 1) * hashSize)
    }
    return derivedKeyBuffer
}

module.exports = {
    KDF2
}