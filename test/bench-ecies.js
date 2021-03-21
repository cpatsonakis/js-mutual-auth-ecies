const crypto = require('crypto')
const ecies = require('../ecies')
const options = require('../options')
const assert = require('assert').strict;

const NS_PER_SEC = 1e9;
const msgNo = 5000
const msgSize = 32

// Generate an array of random messages
msgArray = new Array(msgNo)
for (i = 0; i < msgNo ; ++i) {
    msgArray[i] = crypto.pseudoRandomBytes(msgSize)
}
encArray = new Array(msgNo)


// Generate the ecdh keys of both parties
// Alice is the sender, Bob is the receiver
var alice = crypto.createECDH(options.curveName)
alice.generateKeys()
var alicePrivateKey = alice.getPrivateKey()
var bob = crypto.createECDH(options.curveName)
var bobPubKey = bob.generateKeys()
var bobPrivateKey = bob.getPrivateKey()

// Start with encyptions
var startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    encArray[i] = ecies.encrypt(alicePrivateKey, bobPubKey, msgArray[i])
}
var totalHRTime = process.hrtime(startTime);
var encTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

// Do decryptions now
startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    ecies.decrypt(bobPrivateKey, encArray[i])
}
totalHRTime = process.hrtime(startTime);
var decTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

console.log("Benchmark Inputs: " + msgNo + " messages, message_size = " + msgSize + " bytes")
console.log("Encryption benchmark results: total_time = " + encTimeSecs + " (secs), throughput = " + (msgNo/encTimeSecs) + " (ops/sec), Avg_Op_Time = " + (encTimeSecs/msgNo) + " (secs)")
console.log("Decryption benchmark results: total_time = " + decTimeSecs + " (secs), throughput = " + (msgNo/decTimeSecs) + " (ops/sec), Avg_Op_Time = " + (decTimeSecs/msgNo) + " (secs)")


