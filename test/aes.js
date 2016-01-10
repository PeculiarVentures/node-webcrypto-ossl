var assert = require('assert');

describe("Aes", function () {
    var webcrypto;
    var keys;

    var TEST_MESSAGE = new Buffer("12345678901234561234567890123456");

    before(function (done) {
        webcrypto = global.webcrypto;
        keys = global.keys;
        done();
    })

    it("Aes CBC", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(16));
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;

                return webcrypto.subtle.encrypt(
                    {
                        name: "AES-CBC",

                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        iv: iv
                    },
                    key, //from generateKey or importKey above
                    TEST_MESSAGE //ArrayBuffer of data you want to encrypt
                    )
            })
            .then(function (enc) {
                assert.equal(enc !== null, true, "Has no encrypted value");
                assert.notEqual(enc.length, 0, "Has empty encrypted value");
                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-CBC",
                        iv: iv //The initialization vector you used to encrypt
                    },
                    key, //from generateKey or importKey above
                    enc //ArrayBuffer of the data
                    );
            })
            .then(function (dec) {
                var s = "";
                var buf = new Uint8Array(dec);
                for (var i = 0; i < buf.length; i++) {
                    s += String.fromCharCode(buf[i]);
                }
                assert.equal(s, TEST_MESSAGE.toString(), "AES-CBC encrypt/decrypt is not valid")
            })
            .then(done, done);
    })

    it("Aes CBC JWK export/import", function (done) {
        var key = null;
        var _jwk;
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;

                return webcrypto.subtle.exportKey("jwk", key);
            })
            .then(function (jwk) {
                assert.equal(jwk != null, true, "Has no JWK secretKey");
                assert.equal(jwk.k !== null, true, "Wrong JWK key param");
                assert.equal(jwk.key_ops.length === 4, true, "Wrong JWK key usages amount");
                assert.equal(jwk.alg === "A256CBC", true, "Wrong JWK key algorithm");
                assert.equal(jwk.kty === "oct", true, "Wrong JWK key type");
                assert.equal(jwk.ext, true, "Wrong JWK key extractable");
                _jwk = jwk;
                return webcrypto.subtle.importKey(
                    "jwk",
                    jwk,
                    {
                        name: "AES-CBC"
                    },
                    true,
                    ["encrypt", "decrypt"]
                    );
            })
            .then(function (k) {
                assert.equal(k.type === "secret", true, "Key is not Secret");
                assert.equal(k.algorithm.name === "AES-CBC", true, "Key is not AES-CBC");
                key = k;
                return webcrypto.subtle.exportKey("jwk", k)
            })
            .then(function (jwk) {
                assert.equal(jwk != null, true, "Has no JWK secretKey");
                assert.equal(jwk.k === _jwk.k, true, "Wrong JWK key param");
            })
            .then(done, done);
    })

    it("Aes GCM", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(12));
        webcrypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;

                return webcrypto.subtle.encrypt(
                    {
                        name: "AES-GCM",

                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        iv: iv,
                        //Additional authentication data (optional)
                        additionalData: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,

                        //Tag length (optional)
                        tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
                    },
                    key, //from generateKey or importKey above
                    TEST_MESSAGE //ArrayBuffer of data you want to encrypt
                    )
            })
            .then(function (enc) {
                assert.equal(enc !== null, true, "Has no encrypted value");
                assert.notEqual(enc.length, 0, "Has empty encrypted value");
                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv, //The initialization vector you used to encrypt
                        //Additional authentication data (optional)
                        additionalData: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,

                        //Tag length (optional)
                        tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
                    },
                    key, //from generateKey or importKey above
                    enc //ArrayBuffer of the data
                    );
            })
            .then(function (dec) {
                var s = "";
                var buf = new Uint8Array(dec);
                for (var i = 0; i < buf.length; i++) {
                    s += String.fromCharCode(buf[i]);
                }
                assert.equal(s, TEST_MESSAGE.toString(), "AES-CBC encrypt/decrypt is not valid")
            })
            .then(done, done);
    })

    it("Aes GCM JWK export/import", function (done) {
        var key = null;
        var _jwk;
        webcrypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;

                return webcrypto.subtle.exportKey("jwk", key);
            })
            .then(function (jwk) {
                assert.equal(jwk != null, true, "Has no JWK secretKey");
                assert.equal(jwk.k !== null, true, "Wrong JWK key param");
                assert.equal(jwk.key_ops.length === 4, true, "Wrong JWK key usages amount");
                assert.equal(jwk.alg === "A256GCM", true, "Wrong JWK key algorithm");
                assert.equal(jwk.kty === "oct", true, "Wrong JWK key type");
                assert.equal(jwk.ext, true, "Wrong JWK key extractable");
                _jwk = jwk;
                return webcrypto.subtle.importKey(
                    "jwk",
                    jwk,
                    {
                        name: "AES-GCM"
                    },
                    true,
                    ["encrypt", "decrypt"]
                    );
            })
            .then(function (k) {
                assert.equal(k.type === "secret", true, "Key is not Secret");
                assert.equal(k.algorithm.name === "AES-GCM", true, "Key is not AES-CBC");
                key = k;
                return webcrypto.subtle.exportKey("jwk", k)
            })
            .then(function (jwk) {
                assert.equal(jwk != null, true, "Has no JWK secretKey");
                assert.equal(jwk.k === _jwk.k, true, "Wrong JWK key param");
            })
            .then(done, done);
    })
})