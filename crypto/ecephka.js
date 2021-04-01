'use strict';

const crypto = require('crypto');
const config = require('./config')

function ECEphemeralKeyAgreement() {
    this.ecdh = crypto.createECDH(config.curveName);

    this.generateEphemeralPublicKey = () => {
        return this.ecdh.generateKeys();
    }

    this.generateSharedSecretForPublicKey = (theirECPublicKey) => {
        try {
            this.ecdh.getPublicKey()
        } catch(error) {
            throw new Error('You can\'t generate a shared secret for another public key without calling generateEphemeralPublicKey() first')
        }
        return this.ecdh.computeSecret(theirECPublicKey);
    }

    this.computeSharedSecretFromKeyPair = (myECPrivateKey, theirECPublicKey) => {
        this.ecdh.setPrivateKey(myECPrivateKey);
        return this.ecdh.computeSecret(theirECPublicKey);
    }
}

module.exports = new ECEphemeralKeyAgreement()