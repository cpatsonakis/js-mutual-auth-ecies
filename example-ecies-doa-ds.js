const ecies = require('./ecies-doa-ds'); //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('./crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');

// Generate Alice's EC signing key pair
let aliceECSigningKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
// Generate Bob's ECDH key pair (message receiver)
let bobECDH = crypto.createECDH(curveName)
let bobECDHPublicKey = bobECDH.generateKeys(); 
let bobECDHPrivateKey = bobECDH.getPrivateKey();

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
let encEnvelope = ecies.encrypt(aliceECSigningKeyPair, bobECDHPublicKey, plainTextMessage)
console.log("Encrypted Envelope:")
console.log(encEnvelope)

// ... The encrypted envelope is somehow transmitted to Bob
// Bob receives the encrypted envelope
// Bob decodes the ECDH public key for which this encrypted envelope is intended for
let myECDHPublicKey = ecies.getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope)
// ... Bob searches his key database for the corresponding ECDH private key
// ... We assume here that Bob finds it
assert(Buffer.compare(myECDHPublicKey, bobECDHPublicKey) === 0, "PUBLIC KEYS ARE NOT EQUAL")
// Bob calls the decryption function and gets back an object.
let decEnvelope = ecies.decrypt(bobECDHPrivateKey, encEnvelope)
assert(Buffer.compare(decEnvelope.message, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);