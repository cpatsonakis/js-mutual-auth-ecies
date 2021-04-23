'use strict';

const crypto = require('crypto')

function PublicKeyDeserializer() {
    this.deserializeECDHPublicKey = (ecdhPublicKeySerialized) => {
        let encodingFormat = require('../crypto').encodingFormat;
        return Buffer.from(ecdhPublicKeySerialized, encodingFormat)
    }

    this.deserializeECSigVerPublicKey = (ecSigVerPublicKeySerialized) => {
        let encodingFormat = require('../crypto').encodingFormat;
        return crypto.createPublicKey({
            key: Buffer.from(ecSigVerPublicKeySerialized, encodingFormat),
            format: 'der',
            type: 'spki'
        })
    }

}

module.exports = new PublicKeyDeserializer()