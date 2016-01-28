var assert = require('assert');
var native = require("../buildjs/native")

// console.log(native);

describe("native", function () {

    it("generate RSA 1024,3", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    it("generate RSA 2048,F4", function (done) {
        native.Key.generateRsa(2048, native.RsaPublicExponent.RSA_F4, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    it("generate RSA error", function (done) {
        native.Key.generateRsa(1024, 3, function (err, key) {
            assert(err != null, true, "Must be error on key generation");
            done();
        })
    })

    it("jwk RSA private", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportJwk(native.KeyType.PRIVATE, function (err, jwk) {
                assert(jwk != null, true, "Error on key export");
                assert.equal(jwk.kty, "RSA");
                assert.equal(jwk.d != null, true, "Key is not private");
                native.Key.importJwk(jwk, native.KeyType.PRIVATE, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    it("jwk RSA public", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportJwk(native.KeyType.PUBLIC, function (err, jwk) {
                assert(jwk != null, true, "Error on key export");
                assert.equal(jwk.kty, "RSA");
                assert.equal(jwk.d == null, true, "Key is private");
                native.Key.importJwk(jwk, native.KeyType.PUBLIC, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    it("spki RSA", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportSpki(function (err, raw) {
                assert(raw != null, true, "Error on key export");
                native.Key.importSpki(raw, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    it("pksc8 RSA", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportPkcs8(function (err, raw) {
                assert(raw != null, true, "Error on key export");
                native.Key.importPkcs8(raw, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    function test_sign(key, md, done) {
        var message = new Buffer("Hello");

        key.sign(md, message, function (err, sig) {
            assert(sig != null, true, "Error on sign");
            key.verify(md, message, sig, function (err, v) {
                assert(v, true, "Signature is not valid");
                done();
            })
        })
    }

    it("sign RSA sha1", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            assert.equal(err == null, true, "error on sign");
            test_sign(key, "sha1", done);
        });
    })

    function test_rsa_oaep_enc_dec(md, message, label, done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.RsaOaepEncDec(md, message, label, false, function (err, dec) {
                assert(dec != null, true, "Error on encrypt");
                key.RsaOaepEncDec(md, dec, label, true, function (err, msg) {
                    assert(msg != null, true, "Error on decrypt");
                    assert(Buffer.compare(msg, message) === 0, true, "Wron resul value");
                    done();
                })
            })
        })
    }

    it("encypt RSA OAEP without label", function (done) {
        test_rsa_oaep_enc_dec("sha1", new Buffer("Hello world"), null, done);
    })

    it("encypt RSA OAEP with label", function (done) {
        test_rsa_oaep_enc_dec("sha1", new Buffer("Hello world"), new Buffer("1234567890"), done);
    })

    it("generate EC secp192k1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    it("sign EC secp192k1 sha1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            test_sign(key, "sha1", done);
        })
    })

    it("deriveKey EC secp192k1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveKey(key, 128, function(err, b){
                assert(b != null, true, "Error on key derive");
                done();
            })
        })
    })

})