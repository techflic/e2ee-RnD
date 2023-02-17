/**
 * GCM ( Galois Counter Mode ) - allows us to send authenticated encrypted messages.
 * Security that comes additional with GCM are :
 * 1. Confidentiality: Nobody without the key can read the message.
 * 2. Integrity: Nobody has changes the content of the message.
 * 3. Authenticity: The originator of the message can be verified.
 * 
 * In short, AES256 with GCM means - you need not worry about using MACS or HMACS because all the authentication is handled by GCM itself.
 */



const crypto = require("crypto");
const aes256 = require("aes256");


const alice = crypto.createECDH("secp256k1");
const bob = crypto.createECDH("secp256k1");


alice.generateKeys();
const alicePublicKey = alice.getPublicKey().toString("base64");

bob.generateKeys();
const bobPublicKey = bob.getPublicKey().toString("base64");


const aliceSecret = alice.computeSecret(bobPublicKey, "base64", "hex");

const bobSecret = bob.computeSecret(alicePublicKey, "base64", "hex");


const MESSAGE = "some random message..."


/**
 * STEP 1 :: create cipher.
 * Note - we will not be using any 3rd party for GCM. we will use node built crypto.createCipheriv()
 */
const IV = crypto.randomBytes(16);
// IV is like a salt of encryption and it can be public and it should be random and it should be used only one time per message and this can be prepended to the encrypted message and it should be of 16 bytes

const cipher = crypto.createCipheriv(
    "aes-256-gcm", // 1st param is the algorithm
    Buffer.from(aliceSecret, 'hex'), // 2nd param is the cipher key ( passed as buffer )
    IV // 3rd param is the iv ( initialization vector )
)


/**
 * STEP 2 :: Encrypt the message using cipher.
 */
let encrypted = cipher.update(
    MESSAGE, // 1st param is the message
    "utf8", // 2nd param is the type of the message
    "hex" // 3rd param is the output type
);
encrypted += cipher.final("hex")


/**
 * STEP 3 :: create authentication tag.
 */
const authTag = cipher.getAuthTag().toString("hex")


console.table({ IV: IV.toString("hex"), encrypted: encrypted, authTag: authTag });


/**
 * STEP 4 :: create final payload
 */
const payload =  IV.toString("hex") + encrypted + authTag;
const payloadBase64 = Buffer.from(payload, "hex").toString("base64");




// ( decrypt )
const bob_payload = Buffer.from(payloadBase64, "base64").toString("hex");
const bob_IV = bob_payload.substr(0, 32);
const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32);
const bob_authTag = bob_payload.substr(bob_payload.length - 32, 32);


console.table({ bob_IV: bob_IV.toString("hex"), bob_encrypted: bob_encrypted, bob_authTag: bob_authTag });


try {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        Buffer.from(bobSecret, "hex"),
        Buffer.from(bob_IV, "hex")
    );

    decipher.setAuthTag(Buffer.from(bob_authTag, "hex"));

    let decrypted = decipher.update(bob_encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    console.log("final result : ", decrypted);
} catch (error) {
    console.log("error : ", error);
}
