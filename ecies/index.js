/*
Totally not an implementation that complies to the one illustrated in: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
We have different requirements here bro, so we have to deal with the crypto API of this shit JS library that does not allow us
to do proper crypto operations ON THE SAME FUCKING CURVE MIND YOU. YES, YES INDEED, WE CANNOT USE AN EC KEY PAIR TO DO ECDH
ON THE SAME FUCKING CURVE MIND YOU. NO, THIS LIBRARY JUST REFUSES TO DO SO. Great, just great I tell ya... I mean, really, who
gives a shit about point operations on elliptic curves. Like, I could do some EC co-factor DH, but no no, no sir, this library
just doesn't want me to do it... It begs the existential question right now, why did I learn all this crypto math? So that I can
have this stupid library deny me? I really feel that I am the target of some "library privilege" here, ya know, in the same sense
of "white privilege" (LUL).

Contrary to the typical ECIES scheme, in this paradigm, we want to authenticate the sender to the receiver...
But... We don't want to use digital signatures... Why? Why you ask dear sir? Oh well... ya know... digital
signatures are kinda expensive, like an order, or an oder and a half, magnitude more costly. I mean, who cares
right? We could just do a digital signature based on some EC key pair and be done with it right? But no... no
dear sir... I do not accept this reality... I just have to find a better way... So, is it better? Have I actually
made it better? Well... when I write the test cases we will all find out. Not that I expect anyone to read this message.
Currently, it's 01:00 AM and I'm at my 3rd glass of whiskey - not so hardcore for someone who calls himself a "cryptographer".
I mean, the H2020 project for which this code is going to be part of is just a shitshow. Oops!!! I have signed an NDA, can't talk about
it tee-hee. Fun times! I mean, we are developing an encryption scheme for no reason really. Picture this dear bro who is reading this
message (fist bump), we are dealing with business people who think that hashes = privacy. Yes... yes you read that right, that is what
they think. And we are sitting here, trying to do proper crypto. Like this is a complete sureal situation ye? On the one hand, we have
a bullshit "crypto" library (GMP & LIBGCRYPT SAVE ME!!!!) and, on the other hand, we have to deal with retards. Like, we could serve
them plaintext-based applications and they would still buy it. Ha! Honest to dear baby jesus christ, I was so intrigued on inserting
some kind of backdoor in this fucking implementation to mess up all the demos and fuck-up all their "pilot demonstrations...". That
would be so much fun dude... But, "trust me", I certainly did not do that xD

ON A MORE SERIOUS NOTE:
This "library" (the fuck if you can call it that) is based on the code-base of the dear sir's github repo: https://github.com/bin-y/standard-ecies
Although, to be completely honest, after all the shit that I have done, it looks nothing like it. On the one hand, I am not a JS developer.
Why would I be a JS developer? Why would I offend myself like that? This is a bullshit language that plagues the entire web. How can some people
really go in their lives and claim to be JS developers? Don't they feel any shame? Literally my dudes, full disclosure here, this is the first
time that I am writing JS code (ha!), so I have no fucking idea. In this "language", you just type stuff and everything comes together, what a
fucking joke... NO TYPE CHECKING! "=" ARE NOT ENOUGH WE NEED 3 of those for equality!!! ARRAYS!! HAHA ARRAYS!!! SEMICOLONS!! OBJECTS HAHA!! I
digress... Since I am a very big nerd, and since the people I am dealing with are full-fledged retards, I did, on the one hand, several
simplications and, on the other hand, a couple of modifications to increase security. Like, really dude, who the fuck chooses an
encryption key with 16 bytes of entropy. QUANTUM COMPUTERS AND THE DREAD OF QUANTUM SUPREMACY IS UPON US DEAR LORD!!! PANIC!! PANIC!!!
Hopefully the sarcasm in the previous sentence is evident...
*/
'use strict'; // yes, yes... JS is a very "strict" language...

const crypto = require('crypto');
const assert = require('assert');
const options = require('./options').options

// Symmetric decryption based on the input key. This function assumes
// that we are using a symmetric cipher that does not require an IV
function symmetricEncrypt(cypherName, key, plaintext) {
  let cipher = crypto.createCipheriv(cypherName, key, null);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Symmetric decryption based on the input key. This function assumes
// that we are using a symmetric cipher that does not require an IV
function symmetricDecrypt(cypherName, key, ciphertext) {
  let cipher = crypto.createDecipheriv(cypherName, key, null);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Key MAC function
function macMessage(cypherName, key, message) {
  return crypto.createHmac(cypherName, key).update(message).digest();
}

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

exports.encrypt = function (senderPrivateKey, receiverPublicKey, message) {
  // fuck you, you retarded crypto library that you don't allow me to do EC math
  // on the same curve and I have to do this bullshit transformation in order to
  // protect the public key of the sender. Top notch job that I can't do EC co-factor
  // DH....
  // Ok, so now we have to produce an ECDH shared secret by using the private key
  // of the sender so that we can use it to "authenticate" the message sender to
  // the receiver.

  var senderECDH = crypto.createECDH(options.curveName)
  senderECDH.setPrivateKey(senderPrivateKey)

  // Shared secret that the receiver can produce by knowing the public-key of
  // the sender and by using his own private key
  const senderSharedSecret = senderECDH.computeSecret(receiverPublicKey)
  // Compute a random salt for the MAC to guarantee uniqueness of the authenticator
  const salt = crypto.randomBytes(options.kdfLength)

  var messageEncoded = message.toString('base64url')
  var messageEncodedBuffer = Buffer.from(messageEncoded)

  // Compute the authenticator
  const authTag = macMessage(options.macName,
    senderSharedSecret,
    Buffer.concat([
      salt,
      messageEncodedBuffer],
      salt.length + messageEncodedBuffer.length))

  // Wrap them all in an envelope. We don't need to encrypt the message
  // here because we are going to encrypt the entire envelope with an
  // ephemeral key right after
  var senderAuthMsgEnvelope = {
    from: senderECDH.getPublicKey().toString('base64url'),
    salt: salt.toString('base64url'),
    msg: messageEncoded,
    tag: authTag.toString('base64url')
  }

  const senderAuthMsgEnvelopeSerialized = JSON.stringify(senderAuthMsgEnvelope)

  // Ok, now we are going to compute the ephemeral DH secret based on the public key of the
  // receiver
  var ephemeralSenderECDH = crypto.createECDH(options.curveName)
  const R = ephemeralSenderECDH.generateKeys()

  // Ephemeral Shared Secret
  const ephemeralSharedSecret = ephemeralSenderECDH.computeSecret(receiverPublicKey);

  // Derive the ephemeral encryption key (ephEncKey) and the ephemeral MAC key (ephMACKey)
  // ephEncKey || epcMACKey = KDF(ephemeralSharedSecret)
  const ephemeralKDF = crypto.createHash(options.kdfName).update(ephemeralSharedSecret).digest()

  // Yes yes... we fucking assume that the length of the hash function is divisible by 2
  // Try and find a hash function that doesn't have a byte output with that property you retard...
  const ephemeralEncKey = ephemeralKDF.slice(0, options.kdfLength / 2);
  const ephemeralMACKey = ephemeralKDF.slice(options.kdfLength / 2);

  const serializedEnvelopeCiphertext = symmetricEncrypt(options.symmetricCypherName, ephemeralEncKey, senderAuthMsgEnvelopeSerialized);
  const serializedEnvelopeTag = macMessage(options.macName, ephemeralMACKey, serializedEnvelopeCiphertext);

  return {
    to: receiverPublicKey.toString('base64url'),
    r: R.toString('base64url'),
    ct: serializedEnvelopeCiphertext.toString('base64url'),
    tag: serializedEnvelopeTag.toString('base64url')
  }
};

exports.decrypt = function (receiverPrivateKey, encEnvelope) {
  // Some envelope format checks are warranted first...
  assert(('to' in encEnvelope), "ecies::decrypt(): 'to' property not found on input encrypted envelope")
  assert(('r' in encEnvelope), "ecies::decrypt(): 'r' property not found on input encrypted envelope")
  assert(('ct' in encEnvelope), "ecies::decrypt(): 'ct' property not found on input encrypted envelope")
  assert(('tag' in encEnvelope), "ecies::decrypt(): 'tag' property not found on input encrypted envelope")

  const ephemeralReceiverECDH = crypto.createECDH(options.curveName);
  ephemeralReceiverECDH.setPrivateKey(receiverPrivateKey)

  assert(equalConstTime(ephemeralReceiverECDH.getPublicKey().toString('base64url'), encEnvelope.to),
    "ecies::decrypt(): Public keys do not match")

  // Ephemeral Shared Secret
  const ephemeralSharedSecret = ephemeralReceiverECDH.computeSecret(Buffer.from(encEnvelope.r, 'base64url'));

  // Derive the ephemeral encryption key (ephEncKey) and the ephemeral MAC key (ephMACKey)
  // ephEncKey || epcMACKey = KDF(ephemeralSharedSecret)
  const ephemeralKDF = crypto.createHash(options.kdfName).update(ephemeralSharedSecret).digest()

  // Yes yes... we fucking assume that the length of the hash function is divisible by 2
  // Try and find a hash function that doesn't have a byte output with that property you retard...
  const ephemeralEncKey = ephemeralKDF.slice(0, options.kdfLength / 2);
  const ephemeralMACKey = ephemeralKDF.slice(options.kdfLength / 2);

  const ciphertextBuffer = Buffer.from(encEnvelope.ct, 'base64url')

  const serializedEnvelopeTag = macMessage(options.macName, ephemeralMACKey, ciphertextBuffer);
  assert(equalConstTime(serializedEnvelopeTag.toString('base64url'), encEnvelope.tag), "ecies::decrypt(): Bad MAC")

  var senderAuthMsgEnvelopeSerialized = symmetricDecrypt(options.symmetricCypherName, ephemeralEncKey, ciphertextBuffer)
  var senderAuthMsgEnvelope = JSON.parse(senderAuthMsgEnvelopeSerialized.toString())

  assert(('from' in senderAuthMsgEnvelope), "ecies::decrypt(): 'from' property not found on sender's authenticated envelope")
  assert(('salt' in senderAuthMsgEnvelope), "ecies::decrypt(): 'salt' property not found on sender's authenticated envelope")
  assert(('msg' in senderAuthMsgEnvelope), "ecies::decrypt(): 'msg' property not found on sender's authenticated envelope")
  assert(('tag' in senderAuthMsgEnvelope), "ecies::decrypt(): 'tag' property not found on sender's authenticated envelope")

  var senderPublicKey = Buffer.from(senderAuthMsgEnvelope.from, 'base64url')
  var salt = Buffer.from(senderAuthMsgEnvelope.salt, 'base64url')
  var messageEncodedBuffer = Buffer.from(senderAuthMsgEnvelope.msg)

  var receiverECDH = crypto.createECDH(options.curveName)
  receiverECDH.setPrivateKey(receiverPrivateKey)
  var receiverSharedSecret = receiverECDH.computeSecret(senderPublicKey)

  // Compute the authenticator
  const authTag = macMessage(options.macName,
    receiverSharedSecret,
    Buffer.concat([
      salt,
      messageEncodedBuffer],
      salt.length + messageEncodedBuffer.length))
  assert(equalConstTime(authTag.toString('base64url'), senderAuthMsgEnvelope.tag), "ecies::decrypt(): Bad authenticator")
  return {
    from: senderPublicKey,
    message: Buffer.from(senderAuthMsgEnvelope.msg, 'base64url')
  };
}
