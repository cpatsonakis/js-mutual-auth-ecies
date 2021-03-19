const crypto = require('crypto')
const ecies = require('./ecies')
const eciesOpts = require('./ecies/options').options
const assert = require('assert').strict;

const plainText = Buffer.from('hello world');
var alice = crypto.createECDH(eciesOpts.curveName)
var bob = crypto.createECDH(eciesOpts.curveName)
alicePubKey = alice.generateKeys()
bobPubKey = bob.generateKeys()
console.log(Object.prototype.toString.call(plainText))

encryptedEnvelope = ecies.encrypt(alice.getPrivateKey(), bobPubKey, plainText);

console.log(encryptedEnvelope)
console.log(encryptedEnvelope.kdfIV)


// const encryptedText = ecies.encrypt(alice.getPrivateKey(), bobPubKey, plainText);
// const decryptedText = ecies.decrypt(bob.getPrivateKey(), encryptedText;
// assert(plainText.toString('hex') == decryptedText.toString('hex'));
// console.log("Plain text message: |" + plainText + "|")
// console.log("Decrypted message: |" + decryptedText + "|")