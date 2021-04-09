'use strict';

const crypto = require('crypto');

class ECEphemeralKeyAgreement {

    constructor() {
        let curveName = require('./index').params.curveName;
        this.ecdh = crypto.createECDH(curveName);
    }

    generateEphemeralPublicKey = () => {
        return this.ecdh.generateKeys();
    }

    generateSharedSecretForPublicKey = (theirECDHPublicKey) => {
        try {
            this.ecdh.getPublicKey()
        } catch(error) {
            throw new Error('You cannot generate a shared secret for another public key without calling generateEphemeralPublicKey() first')
        }
        return this.ecdh.computeSecret(theirECDHPublicKey);
    }

    computeSharedSecretFromKeyPair = (myECDHPrivateKey, theirECDHPublicKey) => {
        this.ecdh.setPrivateKey(myECDHPrivateKey);
        return this.ecdh.computeSecret(theirECDHPublicKey);
    }
}

module.exports = ECEphemeralKeyAgreement