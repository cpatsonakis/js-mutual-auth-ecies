const eciesds = require('./eciesds')
const assert = require('assert').strict;

$$ = {Buffer}; 
const pskcrypto = require("./pskcrypto");

const plainTextMessage = 'hello world';
let keyGenerator = pskcrypto.createKeyPairGenerator();
let aliceECKeyPair = keyGenerator.generateKeyPair();
let bobECKeyPair = keyGenerator.generateKeyPair();
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)


let encEnvelope = eciesds.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)
let decEnvelope = eciesds.decrypt(bobECKeyPair.privateKey, encEnvelope)
assert(decEnvelope.from === alicePEMKeyPair.publicKey, "PUBLIC KEYS ARE NOT EQUAL")
console.log("Decrypted Envelope:")
console.log(decEnvelope)

console.log(JSON.stringify(eciesds.config))