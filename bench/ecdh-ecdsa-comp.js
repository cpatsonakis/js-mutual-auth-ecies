const crypto = require('crypto')
const mycrypto = require('../crypto')

$$ = {Buffer}; 
const pskcrypto = require("../pskcrypto");

const NS_PER_SEC = 1e9;
const iterations = 1000

let message = crypto.pseudoRandomBytes(32)
let keyGenerator = pskcrypto.createKeyPairGenerator();
let aliceECKeyPair = keyGenerator.generateKeyPair();
let bobECKeyPair = keyGenerator.generateKeyPair();
let aliceECKeyPairPEM = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

var startTime = process.hrtime();
for (i = 0 ; i < iterations ; ++i) {
    mycrypto.ECEphemeralKeyAgreement.computeSharedSecretFromKeyPair(aliceECKeyPair.privateKey, bobECKeyPair.publicKey)
}
var totalHRTime = process.hrtime(startTime);
var ecdhTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

var startTime = process.hrtime();
for (i = 0 ; i < iterations ; ++i) {
    mycrypto.computeDigitalSignature(aliceECKeyPairPEM.privateKey, message)
}
var totalHRTime = process.hrtime(startTime);
var ecdsaTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

console.log("ECDH Derive Shared Secret vs ECDSA Performance Comparison: " + iterations + " iterations")
console.log("ECDH Derive Shared Secret benchmark results: total_time = " + ecdhTimeSecs + " (secs), throughput = " + (iterations/ecdhTimeSecs) + " (ops/sec), Avg_Op_Time = " + (ecdhTimeSecs/iterations) + " (secs)")
console.log("ECDSA benchmark results: total_time = " + ecdsaTimeSecs + " (secs), throughput = " + (iterations/ecdsaTimeSecs) + " (ops/sec), Avg_Op_Time = " + (ecdsaTimeSecs/iterations) + " (secs)")