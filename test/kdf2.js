const eciesds = require('../eciesds')
const crypto = require('crypto')

function getRandomInt(max) {
    return Math.floor(Math.random() * Math.floor(max));
  }

kdf2 = eciesds.config.evaluateKDF
const maxInputSize = 8
const maxOutputSize = 300
const testIterations = 10000

for(let i = 0 ; i < testIterations ; i++) {
    let curRandomX = crypto.randomBytes(getRandomInt(maxInputSize))
    let curOutputSize = getRandomInt(maxOutputSize)
    let curOutput = kdf2(curRandomX, curOutputSize)
    if (curOutput.length != curOutputSize) {
        throw new Error("output sizes do not match")
    }
}
console.log('success')
