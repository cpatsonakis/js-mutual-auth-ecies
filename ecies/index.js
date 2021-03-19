/*
Totally not an implementation that complies to the one illustrated in: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
We have different requirements here bro, so we have to deal with the crypto API of this shit JS library that does not allow us
to do proper crypto operations ON THE SAME FUCKING CURVE MIND YOU. YES, YES INDEED, WE CANNOT USE AN EC KEY PAIR TO DO ECDH
ON THE SAME FUCKING CURVE MIND YOU. NO, THIS LIBRARY JUST REFUSES TO DO SO. Great, just great I tell ya... I mean, really, who
gives a shit about point operation on elliptic curves. Like, I could do some EC co-factor DH, but no no, no sir, this library
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
Just make it 32 bytes and go and drink your coffee in a care-free fashion. It seems to me that I am not being serious, although I said
I would be serious. Oh well, it is what it is...
*/
'use strict';

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
  let cipher = crypto.createCipheriv(cypherName, key, null);
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
  var ephemeralSenderECDH = crypto.createECDH(options.curvename)
  ephemeralSenderECDH.generateKeys()

  // Ephemeral Shared Secret
  const ephemeralSharedSecret = ephemeralSenderECDH.computeSecret(receiverPublicKey);

  // Derive the ephemeral encryption key (ephEncKey) and the ephemeral MAC key (ephMACKey)
  // ephEncKey || epcMACKey = KDF(ephemeralSharedSecret)
  const ephemeralHash = crypto.createHash(options.kdfName).update(ephemeralSharedSecret).digest()

  // Yes yes... we fucking assume that the length of the hash function is divisible by 2
  // Try and find a hash function that doesn't have a byte output with that property you retard...
  // ephEncKey
  const ephemeralEncKey = ephemeralHash.slice(0, options.kdfLength / 2);
  // epcMACKey
  const ephemeralMACKey = ephemeralHash.slice(options.kdfLength / 2);

  // Now we need to compute the encryption of the ephemeral key
  // and the tag of the ephemeral key for message integrity
  const ephemeralKeyCiphertext = symmetricEncrypt(options.symmetricCypherName, ephemeralEncKey, ephemeralEncKey);
  const ephemeralKeyMAC = macMessage(options.macName, ephemeralMACKey, ephemeralKeyCiphertext);
  /*
     Ok, so now we have an object that pretty much looks like this:
     {
       "to" : <ECDH key of receiver in base64>,
       "key_enc": <...>,
       "key_tag": <...>,
       "ephR": <...>,

     }
  */
  const internalKeyIV = crypto.randomBytes(options.kdfLength / 2)






  // Now we start fixing the "internal" or "nested" ECIES shit...
  var senderECDH = crypto.createECDH(options.curveName)
  senderECDH.setPrivateKey(senderPrivateKey)

  senderSharedSecret = senderECDH.computeSecret(senderECDH.getPublicKey())
  
  



  const cipherText = symmetricEncrypt(options.symmetricCypherName, options.iv, encryptionKey, envelopeEncoded);



  // S
  const sharedSecret = senderECDH.computeSecret(receiverPublicKey);


  var envelope = {
    from: senderECDH.getPublicKey().toString('base64'),
    to: receiverPublicKey.toString('base64'),
    payload: message.toString('base64')
  };
  var envelopeEncoded = JSON.stringify(envelope).toString('base64')

  var kdfIV = crypto.randomBytes(sharedSecret.length)

  // uses KDF to derive a symmetric encryption and a MAC keys:
  // Ke || Km = KDF(S || kdfIV)
  const hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, kdfIV],
      sharedSecret.length + kdfIV.length
    )
  );
  // Ke
  const encryptionKey = hash.slice(0, hash.length / 2);
  // Km
  const macKey = hash.slice(hash.length / 2);

  var macIV = crypto.randomBytes(sharedSecret.length)

  // encrypts the message:
  // c = E(Ke; m);
  const cipherText = symmetricEncrypt(options.symmetricCypherName, options.iv, encryptionKey, envelopeEncoded);

  // computes the tag of encrypted message: 
  // d = MAC(Km; c || macIV)
  const tag = macMessage(options.macName, macKey, Buffer.concat([cipherText, macIV], cipherText.length + macIV.length));
  return {
    ciphertext: cipherText.toString('base64'),
    kdfIV: kdfIV.toString('base64'),
    macIV: macIV.toString('base64'),
    tag: tag.toString('base64')
  };
};

exports.decrypt = function (receiverPrivateKey, envelope) {
  const receiverECDH = crypto.createECDH(options.curveName);
  receiverECDH.setPrivateKey(receiverPrivateKey)

  assert(('ciphertext' in envelope), "ecies::decrypt(): 'ciphertext' property not found on input envelope")
  assert(('kdfIV' in envelope), "ecies::decrypt(): 'kdfIV' property not found on input envelope")
  assert(('macIV' in envelope), "ecies::decrypt(): 'macIV' property not found on input envelope")
  assert(('tag' in envelope), "ecies::decrypt(): 'tag' property not found on input envelope")

  assert(Buffer.from(envelope.ciphertext, 'base64').toString('base64') === envelope.ciphertext,
    "ecies::decrypt(): 'ciphertext' is not in base64 encoding")
  assert(Buffer.from(envelope.kdfIV, 'base64').toString('base64') === envelope.kdfIV,
    "ecies::decrypt(): 'kdfIV' is not in base64 encoding")
  assert(Buffer.from(envelope.macIV, 'base64').toString('base64') === envelope.macIV,
    "ecies::decrypt(): 'macIV' is not in base64 encoding")
  assert(Buffer.from(envelope.tag, 'base64').toString('base64') === envelope.tag,
    "ecies::decrypt(): 'tag' is not in base64 encoding")

  // S
  const sharedSecret = receiverECDH.computeSecret(senderPublicKey);

  // uses KDF to derive a symmetric encryption and a MAC keys:
  // Ke || Km = KDF(S || kdfIV)
  const hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, kdfIV],
      sharedSecret.length + kdfIV.length
    )
  );

  const publicKeyLength = receiverECDH.getPublicKey(null, options.keyFormat).length;
  // R
  const R = message.slice(0, publicKeyLength);
  // c
  const cipherText = message.slice(publicKeyLength, message.length - options.macLength);
  // d
  const messageTag = message.slice(message.length - options.macLength);



  // // derives keys the same way as Alice did:
  // // Ke || Km = KDF(S || S1)
  // const hash = hashMessage(
  //   options.hashName,
  //   Buffer.concat(
  //     [sharedSecret, options.s1],
  //     sharedSecret.length + options.s1.length
  //   )
  // );
  // Ke
  const encryptionKey = hash.slice(0, hash.length / 2);
  // Km
  const macKey = hash.slice(hash.length / 2);

  // uses MAC to check the tag
  const keyTag = macMessage(
    options.macName,
    macKey,
    Buffer.concat(
      [cipherText, options.s2],
      cipherText.length + options.s2.length
    )
  );

  // outputs failed if d != MAC(Km; c || S2);
  assert(equalConstTime(messageTag, keyTag), "Bad MAC");

  // uses symmetric encryption scheme to decrypt the message
  // m = E-1(Ke; c)
  return symmetricDecrypt(options.symmetricCypherName, options.iv, encryptionKey, cipherText);
}
