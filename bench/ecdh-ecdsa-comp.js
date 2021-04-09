const crypto = require('crypto')
const mycrypto = require('../crypto')
const curveName = require('../crypto').params.curveName; //get the default named curve

const NS_PER_SEC = 1e9;
const iterations = 1000

let message = crypto.pseudoRandomBytes(32)

let aliceECDH = crypto.createECDH(curveName)
aliceECDH.generateKeys()
let aliceECDHPrivateKey = aliceECDH.getPrivateKey()
let aliceECSigningKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
// Generate Bob's ECDH key pair (message receiver)
let bobECDH = crypto.createECDH(curveName)
let bobECDHPublicKey = bobECDH.generateKeys(); 

var startTime = process.hrtime();
for (i = 0 ; i < iterations ; ++i) {
    let ephemeralKA = new mycrypto.ECEphemeralKeyAgreement()
    ephemeralKA.computeSharedSecretFromKeyPair(aliceECDHPrivateKey, bobECDHPublicKey)
}
var totalHRTime = process.hrtime(startTime);
var ecdhTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

var startTime = process.hrtime();
for (i = 0 ; i < iterations ; ++i) {
    mycrypto.computeDigitalSignature(aliceECSigningKeyPair.privateKey, message)
}
var totalHRTime = process.hrtime(startTime);
var ecdsaTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

console.log("ECDH Derive Shared Secret vs ECDSA Performance Comparison: " + iterations + " iterations")
console.log("ECDH Derive Shared Secret benchmark results: total_time = " + ecdhTimeSecs + " (secs), throughput = " + (iterations/ecdhTimeSecs) + " (ops/sec), Avg_Op_Time = " + (ecdhTimeSecs/iterations) + " (secs)")
console.log("ECDSA benchmark results: total_time = " + ecdsaTimeSecs + " (secs), throughput = " + (iterations/ecdsaTimeSecs) + " (ops/sec), Avg_Op_Time = " + (ecdsaTimeSecs/iterations) + " (secs)")