
// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
    if (b1.length !== b2.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < b1.length; i++) {
        result |= b1[i] ^ b2[i];  // jshint ignore:line
    }
    return result === 0;
}

module.exports = {
    equalConstTime
}