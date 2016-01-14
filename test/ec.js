var assert = require('assert');
var crypto = require('crypto');

function testDeriveKey(webcrypto, namedCurve, algName, keySize, done) {
    var promise = new Promise(function (resolve, reject) {
        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: namedCurve, //can be "P-256", "P-384", or "P-521"
            },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey"] //can be any combination of "deriveKey"
            )
            .then(function (k) {
                assert.equal(k.privateKey !== null, true, "Has no private key");
                assert.equal(k.publicKey !== null, true, "Has no public key");
                key = k;
                return webcrypto.subtle.deriveKey(
                    {
                        name: "ECDH",
                        namedCurve: namedCurve, //can be "P-256", "P-384", or "P-521"
                        public: k.publicKey, //an ECDH public key from generateKey or importKey
                    },
                    k.privateKey, //your ECDH private key from generateKey or importKey
                    { //the key type you want to create based on the derived bits
                        name: algName, //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                        //the generateKey parameters for that type of algorithm
                        length: keySize, //can be  128, 192, or 256
                    },
                    false, //whether the derived key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
                    )
            })
            .then(function (key) {
                assert.equal(key != null, true, "Has no derived Key value");
                assert.equal(key._key != null, true, "Has no derived Key value");
                assert.equal(key.type === "secret", true, "Derived key is not Secret");
            })
            .then(resolve, reject);
    })
    promise = promise.then(done, done);
}

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

    it("Ecdsa export/import PKCS8", function (done) {

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
                key = k;
                return webcrypto.subtle.exportKey(
                    "pkcs8",
                    key.privateKey
                    );
            })
            .then(function (pkcs8) {
                assert.equal(pkcs8 instanceof ArrayBuffer, true, "pkcs8 is not ArrayBuffer");
                return webcrypto.subtle.importKey(
                    "pkcs8",
                    pkcs8,
                    {
                        name: "ECDSA",
                        namedCurve: "P-192", 	//can be "P-256", "P-384", or "P-521"
                    },
                    false, 						//whether the key is extractable (i.e. can be used in exportKey)
                    ["sign", "verify"] 			//can be any combination of "sign" and "verify"
                    )
            })
            .then(function (k) {
                assert.equal(k.type === "private", true, "Key is not Private");
                assert.equal(k.algorithm.name === "ECDSA", true, "Key is not ECDSA");
            })
            .then(done, done);
    })

    it("Ecdsa export/import SPKI", function (done) {

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
                key = k;
                return webcrypto.subtle.exportKey(
                    "spki",
                    key.publicKey
                    );
            })
            .then(function (spki) {
                assert.equal(spki instanceof ArrayBuffer, true, "spki is not ArrayBuffer");
                return webcrypto.subtle.importKey(
                    "spki",
                    spki,
                    {
                        name: "ECDSA",
                        namedCurve: "P-192",
                    },
                    false,
                    ["verify"]
                    )
            })
            .then(function (k) {
                assert.equal(k.type === "public", true, "Key is not Public");
                assert.equal(k.algorithm.name === "ECDSA", true, "Key is not ECDSA");
            })
            .then(done, done);
    })

    it("Ecdsa JWK export/import", function (done) {
        var _jwk;
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
                assert.equal(jwk.x !== null, true, "Wrong EC key param");
                assert.equal(jwk.y !== null, true, "Wrong EC key param");
                assert.equal(jwk.d !== null, true, "Wrong EC key param");
                assert.equal(jwk.crv !== null, true, "Wrong EC key param");
                _jwk = jwk;
                return webcrypto.subtle.importKey(
                    "jwk",
                    jwk,
                    {
                        name: "ECDSA",
                        namedCurve: "P-192"
                    },
                    false,
                    ["sign"]
                    );
            })
            .then(function (k) {
                assert.equal(k.type === "private", true, "Key is not Private");
                assert.equal(k.algorithm.name === "ECDSA", true, "Key is not ECDSA");
                key = k;
                return webcrypto.subtle.exportKey("jwk", k)
            })
            .then(function (jwk) {
                assert.equal(jwk.x === _jwk.x, true, "Wrong EC key param");
                assert.equal(jwk.y === _jwk.y, true, "Wrong EC key param");
                assert.equal(jwk.d === _jwk.d, true, "Wrong EC key param");
                return webcrypto.subtle.sign(
                    {
                        name: "ECDSA",
                        hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                    },
                    key,
                    TEST_MESSAGE)
            })
            .then(function (sig) {
                assert.equal(sig !== null, true, "Has no signature value");
                assert.notEqual(sig.length, 0, "Has empty signature value");
            })
            .then(done, done);
    })

    it("Ecdh derive AES-CBC 128", function (done) {
        testDeriveKey(webcrypto, "P-192", "AES-CBC", 128, done)
    })
    
    it("Ecdh derive AES-CBC 256", function (done) {
        testDeriveKey(webcrypto, "P-192", "AES-CBC", 256, done)
    })
    
    it("Ecdh derive AES-GCM 128", function (done) {
        testDeriveKey(webcrypto, "P-192", "AES-GCM", 128, done)
    })
    
    it("Ecdh derive AES-GCM 256", function (done) {
        testDeriveKey(webcrypto, "P-192", "AES-GCM", 256, done)
    })

    it("Ecdh export/import PKCS8", function (done) {

        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-192",
            },
            false,
            ["decrypt", "encrypt"]
            )
            .then(function (k) {
                key = k;
                return webcrypto.subtle.exportKey(
                    "pkcs8",
                    key.privateKey
                    );
            })
            .then(function (pkcs8) {
                assert.equal(pkcs8 instanceof ArrayBuffer, true, "pkcs8 is not ArrayBuffer");
                return webcrypto.subtle.importKey(
                    "pkcs8",
                    pkcs8,
                    {
                        name: "ECDH",
                        namedCurve: "P-192",
                    },
                    false,
                    ["decrypt"]
                    )
            })
            .then(function (k) {
                assert.equal(k.type === "private", true, "Key is not Private");
                assert.equal(k.algorithm.name === "ECDH", true, "Key is not ECDH");
            })
            .then(done, done);
    })

    it("Ecdsa export/import SPKI", function (done) {

        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-192",
            },
            false,
            ["decrypt", "encrypt"]
            )
            .then(function (k) {
                key = k;
                return webcrypto.subtle.exportKey(
                    "spki",
                    key.publicKey
                    );
            })
            .then(function (spki) {
                assert.equal(spki instanceof ArrayBuffer, true, "spki is not ArrayBuffer");
                return webcrypto.subtle.importKey(
                    "spki",
                    spki,
                    {
                        name: "ECDH",
                        namedCurve: "P-192",
                    },
                    false,
                    ["encrypt"]
                    )
            })
            .then(function (k) {
                assert.equal(k.type === "public", true, "Key is not Public");
                assert.equal(k.algorithm.name === "ECDH", true, "Key is not ECDH");
            })
            .then(done, done);
    })
})