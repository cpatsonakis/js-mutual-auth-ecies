const ecies = require('./ecies'); //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys etc.
const curveName = require('./crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');

// Generate Bob's ECDH key pair (message receiver)
let bobECDH = crypto.createECDH(curveName)
let bobECDHPublicKey = bobECDH.generateKeys(); 
let bobECDHPrivateKey = bobECDH.getPrivateKey();

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(bobECDHPublicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)

// ... Message is somehow transmitted to Bob
// Bob receives the message
let myECDHPublicKey = ecies.getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
// ... Bob searches his key database for the corresponding ECDH private key
assert(Buffer.compare(myECDHPublicKey, bobECDHPublicKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")
// Bob calls the decryption function and gets back an object.
let decMessage = ecies.decrypt(bobECDHPrivateKey, encEnvelope)
assert(Buffer.compare(decMessage, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
// Here is the decrypted message!
console.log('Decrypted message is: ' + decMessage);