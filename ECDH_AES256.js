/**
 * Now, lets encrypt and decrypt using 'shared secret' key generated using ECDH.
 * Note - we will be using AES256 algorithm.
 */



const crypto = require("crypto");


const alice = crypto.createECDH("secp256k1");
const bob = crypto.createECDH("secp256k1");


alice.generateKeys();
const alicePublicKey = alice.getPublicKey().toString("base64");

bob.generateKeys();
const bobPublicKey = bob.getPublicKey().toString("base64");


const aliceSecret = alice.computeSecret(bobPublicKey, "base64", "hex");

const bobSecret = bob.computeSecret(alicePublicKey, "base64", "hex");


/**
 * 3rd party lib
 */
const aes256 = require("aes256");

/**
 * STEP 1 :: Encrypt plain text using AES256 algorithm. This algo will be hashing the plaintext using SHA256 algorithm into 256 bits again.
 */
const MESSAGE = "some random message..."
const encrypted = aes256.encrypt(
    aliceSecret, // 1st param is the key. Note - Even if you don't pass 256 bit key here, lib will automatically create key using SHA256 algorithm for you.
    MESSAGE, // 2nd param is the plaintext
);


/**
 * now this ecrypted will be somehow transmitted to bob
 */


/**
 * STEP 2 :: Decrypt the encrypted message using AES256 algorithm.
 */
const decrypted = aes256.decrypt(bobSecret, encrypted);


/**
 * Finally we have the message
 */
console.log("decrypted message : ", decrypted);


/**
 * Further, at both receiving ends you need to authenticate the encrypted message ( to be sure that encrypted message is sent by alice )
 * We can use GCM ( Galois Counter Mode )
 */