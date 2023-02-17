/**
 * We will be generating a share secret key between two clients ( alice and bob ) using Elliptic Curve Diffie Hellman (ECDH).
 * Here, a common elliptic curve is used as the key.
 * Elliptic curves are much more powerful in a way that they are more secure and more over they require less computing power for same amount of security provided by traditional diffie hellman.
 * Note - The 'shared secret' key generated using ECDH which is 256 bits long is as secure as 3072 bits long 'shared secret' key generated by traditional diffie hellman.
 * 
 * Equation : y^2 = x^3 + ax + b
 * In Traditional Diffie Hellman we have p (prime number) and g (generator), and here we have 'a' and 'b' depending on the value of 'a' and 'b' the shape of the curve changes.
 */



/**
 * built by NodeJs
 */
const crypto = require("crypto");


/**
 * listing down the curves which Node crypto modules has.
 */
console.log(crypto.getCurves())
/**
 * we will be using curve 'secp256k1'
 * Note - This curve is also used by BITCOINS. It gives us a 'shared secret' that is 256 bits long.
 */


/**
 * STEP 1 : initialize alice and bod with same curve name
 */
const alice = crypto.createECDH("secp256k1");
const bob = crypto.createECDH("secp256k1");


/**
 * STEP 2 :: generate 'public' and 'private' keys
 */
alice.generateKeys();
const alicePublicKey = alice.getPublicKey().toString("base64"); // Note - since we need to transmit public key to bob. base64 format is the most typical way.

bob.generateKeys();
const bobPublicKey = bob.getPublicKey().toString("base64");


/**
 * STEP 3 :: generate the 'shared secret' key
 */
const aliceSecret = alice.computeSecret(
    bobPublicKey, // 1st param is the other public key.
    "base64", // 2nd param is type of input we are passing.
    "hex" // 3rd param is the output type expected.
);

const bobSecret = bob.computeSecret(
    alicePublicKey,
    "base64",
    "hex"
);


/**
 * Finally compare 'share secret' key generated by both clients. Now this is to be used to encrypt and decrypt messages in any of the cipher algorithms like AES, etc.
 */
console.log("aliceSecret ==== bobSecret :: ", aliceSecret === bobSecret);