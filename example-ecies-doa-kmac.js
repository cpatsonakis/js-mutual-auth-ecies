const ecies = require('./ecies-doa-kmac')
const assert = require('assert').strict;

$$ = {Buffer}; 
const pskcrypto = require("./pskcrypto");

const plainTextMessage = 'hello world';
let keyGenerator = pskcrypto.createKeyPairGenerator();
let aliceECKeyPair = keyGenerator.generateKeyPair();
let bobECKeyPair = keyGenerator.generateKeyPair();


let encEnvelope = ecies.encrypt(aliceECKeyPair, bobECKeyPair.publicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)
let decEnvelope = ecies.decrypt(bobECKeyPair.privateKey, encEnvelope)
assert(Buffer.compare(decEnvelope.from, aliceECKeyPair.publicKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")
console.log("Decrypted Envelope:")
console.log(decEnvelope)
