var assert = require('assert');
var crypto = require('crypto');

describe("EC", function () {
    var webcrypto;
    var keys;

    before(function (done) {
        webcrypto = global.webcrypto;
        keys = global.keys;
        done();
    })

    var TEST_MESSAGE = new Buffer("This is test message for crypto functions");

    it("Ecdsa", function (done) {

        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-192", 	//can be "P-256", "P-384", or "P-521"
            },
            false, 						//whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] 			//can be any combination of "sign" and "verify"
            )
            .then(function (k) {
                assert.equal(k.privateKey !== null, true, "Has no private key");
                assert.equal(k.publicKey !== null, true, "Has no public key");
                key = k;
                return webcrypto.subtle.sign(
                    {
                        name: "ECDSA",
                        hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                    },
                    key.privateKey,
                    TEST_MESSAGE)
            })
            .then(function (sig) {
                assert.equal(sig !== null, true, "Has no signature value");
                assert.notEqual(sig.length, 0, "Has empty signature value");
                return webcrypto.subtle.verify(
                    {
                        name: "ECDSA",
                        hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                    },
                    key.publicKey,
                    sig,
                    TEST_MESSAGE
                    )
            })
            .then(function (v) {
                assert.equal(v, true, "Ecdsa signature is not valid");
            })
            .then(done, done);
    })

    it("Ecdsa JWK export", function (done) {

        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-192", 	//can be "P-256", "P-384", or "P-521"
            },
            false, 						//whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] 			//can be any combination of "sign" and "verify"
            )
            .then(function (k) {
                assert.equal(k.privateKey !== null, true, "Has no private key");
                assert.equal(k.publicKey !== null, true, "Has no public key");
                key = k;
                return webcrypto.subtle.exportKey(
                    "jwk",
                    key.privateKey
                );
            })
            .then(function (jwk) {
                console.log(jwk);
            })
            .then(done, done);
    })

    it("Ecdh", function (done) {
        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
            },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey"] //can be any combination of "deriveKey"
            )
            .then(function (k) {
                assert.equal(k.privateKey !== null, true, "Has no private key");
                assert.equal(k.publicKey !== null, true, "Has no public key");
                key = k;
                keys.push(key)
                return webcrypto.subtle.deriveKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
                        public: k.publicKey, //an ECDH public key from generateKey or importKey
                    },
                    k.privateKey, //your ECDH private key from generateKey or importKey
                    { //the key type you want to create based on the derived bits
                        name: "AES-CBC", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                        //the generateKey parameters for that type of algorithm
                        length: 128, //can be  128, 192, or 256
                    },
                    false, //whether the derived key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
                    )
            })
            .then(function (key) {
                assert.equal(key != null, true, "Has no derived Key value");
                assert.equal(key._key != null, true, "Has no derived Key value");
            })
            .then(done, done);
    })
})