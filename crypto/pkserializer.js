'use strict';


function PublicKeySerializer() {

    this.serializeECDHPublicKey = (ecdhPublicKey) => {
        let encodingFormat = require('../crypto').encodingFormat;
        return ecdhPublicKey.toString(encodingFormat);
    }

    this.serializeECSigVerPublicKey = (ecSigVerPublicKey) => {
        let encodingFormat = require('../crypto').encodingFormat;
        return ecSigVerPublicKey.export({
            type: 'spki',
            format: 'der'
        }).toString(encodingFormat)
    }
}

module.exports = new PublicKeySerializer()