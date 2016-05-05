var assert = require("assert");
var webcrypto = require('./test/config');

function done(e) {
    if (e)
        console.log("Error", e);
    else
        console.log("Success");
}

var key = null;
var label = null;
// Geberate RSA key
webcrypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([3]),
    hash: {
        name: "SHA-1"
    }
},
    false,
    ["encrypt", "decrypt"]
)
    .then(function (k) {
        assert.equal(k.privateKey !== null, true, "Has no private key");
        assert.equal(k.publicKey !== null, true, "Has no public key");
        key = k;
        return webcrypto.subtle.exportKey("pkcs8", k.privateKey);
    })
    .then(function (pkcs8) {
        assert.equal(pkcs8 instanceof ArrayBuffer, true, "Is empty exported RSA key");
        return webcrypto.subtle.importKey("pkcs8", pkcs8, {
            name: "RSA-OAEP",
            hash: {
                name: "SHA-1"
            }
        },
            false,
            ["decrypt"])
    })
    .then(function (key) {
        assert.equal(!!key, true, "Key is empty");
        assert.equal(key.algorithm.name, "RSA-OAEP", "Wrong algorithm name");
        assert.equal(key.extractable, false, "Wrong extractable param");
        assert.equal(key.usages.length, 1, "Wrong key usages length");
        assert.equal(key.usages[0], "encrypt", "Wrong key usages value");
        assert.equal(key.algorithm.modulusLength, 2048, "Wrong modulus length value");
        assert.equal(key.algorithm.publicExponent.length, 1, "Wrong public exponent value");
        assert.equal(key.type, "private", "Wrong key type");
    })
    .then(done, done);