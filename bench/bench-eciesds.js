const eciesds = require('../eciesds')
const crypto = require('crypto')
$$ = {Buffer}; //??? What the heck is this thing???
const pskcrypto = require("../pskcrypto");


const NS_PER_SEC = 1e9;
const msgNo = 5000
const msgSize = 100

// Generate an array of random messages
msgArray = new Array(msgNo)
for (i = 0; i < msgNo ; ++i) {
    msgArray[i] = crypto.pseudoRandomBytes(msgSize)
}
encArray = new Array(msgNo)

let keyGenerator = pskcrypto.createKeyPairGenerator();
let aliceECKeyPair = keyGenerator.generateKeyPair();
let bobECKeyPair = keyGenerator.generateKeyPair();
let alicePEMKeyPair = keyGenerator.getPemKeys(aliceECKeyPair.privateKey, aliceECKeyPair.publicKey)

// Start with encyptions
var startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    encArray[i] = eciesds.encrypt(alicePEMKeyPair, bobECKeyPair.publicKey, msgArray[i])
}
var totalHRTime = process.hrtime(startTime);
var encTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

// Do decryptions now
startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    eciesds.decrypt(bobECKeyPair.privateKey, encArray[i])
}
totalHRTime = process.hrtime(startTime);
var decTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

console.log("ECIESDS Benchmark Inputs: " + msgNo + " messages, message_size = " + msgSize + " bytes")
console.log("Encryption benchmark results: total_time = " + encTimeSecs + " (secs), throughput = " + (msgNo/encTimeSecs) + " (ops/sec), Avg_Op_Time = " + (encTimeSecs/msgNo) + " (secs)")
console.log("Decryption benchmark results: total_time = " + decTimeSecs + " (secs), throughput = " + (msgNo/decTimeSecs) + " (ops/sec), Avg_Op_Time = " + (decTimeSecs/msgNo) + " (secs)")


