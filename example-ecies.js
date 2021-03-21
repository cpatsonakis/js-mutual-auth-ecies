const crypto = require('crypto')
const ecies = require('./ecies')
const options = require('./options')
const assert = require('assert').strict;

const plainTextMessage = Buffer.from('hello world');

var alice = crypto.createECDH(options.curveName)
var alicePubKey = alice.generateKeys()
var bob = crypto.createECDH(options.curveName)
var bobPubKey = bob.generateKeys()


var encEnvelope = ecies.encrypt(alice.getPrivateKey(), bobPubKey, plainTextMessage)
var decEnvelope = ecies.decrypt(bob.getPrivateKey(), encEnvelope)
assert(Buffer.compare(plainTextMessage, decEnvelope.message) === 0, "MESSAGES ARE NOT EQUAL")
assert(Buffer.compare(decEnvelope.from, alicePubKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")

console.log("Decrypted message is: " + decEnvelope.message.toString())