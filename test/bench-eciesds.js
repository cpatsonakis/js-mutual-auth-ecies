const crypto = require('crypto')
const eciesds = require('../eciesds')
const options = require('../options')

const NS_PER_SEC = 1e9;
const msgNo = 5000
const msgSize = 100

// Generate an array of random messages
msgArray = new Array(msgNo)
for (i = 0; i < msgNo ; ++i) {
    msgArray[i] = crypto.pseudoRandomBytes(msgSize)
}
encArray = new Array(msgNo)

const aliceECKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: options.curveName,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'sec1',
        format: 'pem'
    }
})

const bobECDH = crypto.createECDH(options.curveName)
bobECDHPublicKey = bobECDH.generateKeys()
bobECDHPrivateKey = bobECDH.getPrivateKey()

// Start with encyptions
var startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    encArray[i] = eciesds.encrypt(aliceECKeyPair, bobECDHPublicKey, msgArray[i])
}
var totalHRTime = process.hrtime(startTime);
var encTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

// Do decryptions now
startTime = process.hrtime();
for (i = 0 ; i < msgNo ; ++i) {
    eciesds.decrypt(bobECDHPrivateKey, encArray[i])
}
totalHRTime = process.hrtime(startTime);
var decTimeSecs = (totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC

console.log("ECIESDS Benchmark Inputs: " + msgNo + " messages, message_size = " + msgSize + " bytes")
console.log("Encryption benchmark results: total_time = " + encTimeSecs + " (secs), throughput = " + (msgNo/encTimeSecs) + " (ops/sec), Avg_Op_Time = " + (encTimeSecs/msgNo) + " (secs)")
console.log("Decryption benchmark results: total_time = " + decTimeSecs + " (secs), throughput = " + (msgNo/decTimeSecs) + " (ops/sec), Avg_Op_Time = " + (decTimeSecs/msgNo) + " (secs)")


