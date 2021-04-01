const ecies = require('./ecies-doa-ds') //import the ECIES module
const assert = require('assert').strict;
// The next two lines are required to properly import and initialize the pskcrypto module
$$ = {Buffer}; 
const pskcrypto = require("./pskcrypto");
// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');
let keyGenerator = pskcrypto.createKeyPairGenerator(); // Object that allows us to generate EC key pairs
let aliceECKeyPair = keyGenerator.generateKeyPair(); // Generate Alice's EC key pair (message sender)
let bobECKeyPair = keyGenerator.generateKeyPair(); // Generate Bob's EC key pair (message receiver)

// We have to convert Alice's key pair to PEM format because that's what the encryption function expects
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)
// Bob calls the decryption function and gets back an object.
let decEnvelope = ecies.decrypt(bobECKeyPair.privateKey, encEnvelope)
assert(Buffer.compare(decEnvelope.message, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
assert(decEnvelope.from === alicePEMKeyPair.publicKey, "PUBLIC KEYS ARE NOT EQUAL")
console.log("Decrypted Envelope:")
console.log(decEnvelope)
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);