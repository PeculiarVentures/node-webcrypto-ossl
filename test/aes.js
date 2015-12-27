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

    /*
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
                        //Recommended to use 12 bytes length
                        iv: iv,

                        //Additional authentication data (optional)
                        additionalData: null,

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
                        additionalData: null, //The addtionalData you used to encrypt (if any)
                        tagLength: 128, //The tagLength you used to encrypt (if any)
                    },
                    key, //from generateKey or importKey above
                    enc //ArrayBuffer of the data
                    );
            })
            .then(function (dec) {
                assert.equal(dec.toString(), TEST_MESSAGE.toString(), "AES-GCM encrypt/decrypt is not valid")
            })
            .then(done, done);
    })
    */

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
                assert.equal(dec.toString(), TEST_MESSAGE.toString(), "AES-CBC encrypt/decrypt is not valid")
            })
            .then(done, done);
    })
})