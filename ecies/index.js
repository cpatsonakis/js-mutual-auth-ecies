'use strict';

module.exports = {
  encrypt: require('./encrypt').encrypt,
  decrypt: require('./decrypt').decrypt,
  getDecodedECDHPublicKeyFromEncEnvelope: require('./utils').getDecodedECDHPublicKeyFromEncEnvelope
}