const crypto = require('crypto')
const options = require('./options')
const eciesds = require('./eciesds')
const assert = require('assert').strict;

const plainTextMessage = Buffer.from('hello world');

const KEYFORMAT = "der"

$$ = {Buffer};
let pskcrypto = require("../epi-workspace/privatesky/modules/pskcrypto");

/*
const aliceECKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: options.curveName,
    publicKeyEncoding: {
        type: 'spki',
        format: KEYFORMAT
    },
    privateKeyEncoding: {
        type: 'sec1',
        format: KEYFORMAT
    }
})

const bobECKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: options.curveName,
    publicKeyEncoding: {
        type: 'spki',
        format: KEYFORMAT
    },
    privateKeyEncoding: {
        type: 'sec1',
        format: KEYFORMAT
    }
})
*/

/*const bobECDH = crypto.createECDH(options.curveName)
bobECDHPublicKey = bobECDH.generateKeys() */

let keyGenerator = pskcrypto.createKeyPairGenerator();
let aliceECKeyPair = keyGenerator.generateKeyPair();
let alicePemKeys = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey);

let bobECKeyPair = keyGenerator.generateKeyPair();
let bobPemKeys = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey);


let encEnvelope = eciesds.encrypt(alicePemKeys, bobECKeyPair.publicKey, plainTextMessage)
console.log(encEnvelope);
let decEnvelope = eciesds.decrypt(bobECKeyPair.privateKey, encEnvelope)
assert(Buffer.compare(plainTextMessage, decEnvelope.message) === 0, "MESSAGES ARE NOT EQUAL")
assert(decEnvelope.from === alicePemKeys.publicKey, "PUBLIC KEYS ARE NOT EQUAL")
console.log("Decrypted message is: " + decEnvelope.message.toString());

