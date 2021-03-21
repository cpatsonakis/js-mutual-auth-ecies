const crypto = require('crypto')
const options = require('./options')
const eciesds = require('./eciesds')
const assert = require('assert').strict;

const plainTextMessage = Buffer.from('hello world');

const aliceECKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: options.curveName,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'sec1',
        format: 'pem'
    }
})

const bobECDH = crypto.createECDH(options.curveName)
bobECDHPublicKey = bobECDH.generateKeys()

var encEnvelope = eciesds.encrypt(aliceECKeyPair, bobECDHPublicKey, plainTextMessage)
console.log(encEnvelope)
var decEnvelope = eciesds.decrypt(bobECDH.getPrivateKey(), encEnvelope)
assert(Buffer.compare(plainTextMessage, decEnvelope.message) === 0, "MESSAGES ARE NOT EQUAL")
assert(decEnvelope.from === aliceECKeyPair.publicKey, "PUBLIC KEYS ARE NOT EQUAL")
console.log("Decrypted message is: " + decEnvelope.message.toString())