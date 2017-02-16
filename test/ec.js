"use strict";
const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;

describe("WebCrypto EC", () => {

    var TEST_MESSAGE = new Buffer("1234567890123456");
    var KEYS = [
        { alg: "ECDSA", usages: ["sign", "verify"] },
        { alg: "ECDH", usages: ["deriveKey", "deriveBits"] },
    ];
    var DIGEST = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    var NAMED_CURVES = ["P-256", "P-384", "P-521"];

    var keys = [];

    context("Generate key", () => {

        it("Params", done => {
            webcrypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            )
                .then(keyPair => {
                    let pkey = keyPair.privateKey;
                    assert.equal(pkey.type, "private");
                    assert.equal(pkey.algorithm.name, "ECDSA");
                    assert.equal(pkey.algorithm.namedCurve, "P-256");
                    assert.equal(pkey.extractable, false);
                    assert.equal(pkey.usages.toString(), "sign");

                    let pubKey = keyPair.publicKey;
                    assert.equal(pubKey.type, "public");
                    assert.equal(pubKey.algorithm.name, "ECDSA");
                    assert.equal(pubKey.algorithm.namedCurve, "P-256");
                    assert.equal(pubKey.extractable, true);
                    assert.equal(pubKey.usages.toString(), "");
                })
                .then(done, done);
        });

        // Keys
        KEYS.forEach(key => {
            // namedCurve
            NAMED_CURVES.forEach(namedCurve => {
                var keyName = `${key.alg} crv:${namedCurve}`
                var keyTemplate = {
                    name: keyName,
                    privateKey: null,
                    publicKey: null,
                    usages: key.usages,
                }
                keys.push(keyTemplate);
                it(keyName, done => {
                    var alg = {
                        name: key.alg,
                        namedCurve: namedCurve
                    };
                    webcrypto.subtle.generateKey(alg, true, key.usages)
                        .then(keyPair => {
                            assert.equal(!!(keyPair.privateKey || keyPair.publicKey), true, "KeyPair is empty");
                            // save  keys for next tests
                            keyTemplate.privateKey = keyPair.privateKey;
                            keyTemplate.publicKey = keyPair.publicKey;

                            return Promise.resolve();
                        })
                        .then(done, done);
                });
            });
        });
    });

    context("Sign/Verify", () => {

        keys.filter(key => key.usages.some(usage => usage === "sign"))
            .forEach(key => {
                // Hash
                DIGEST.forEach(hash => {
                    it(`${hash}\t${key.name}`, done => {
                        var alg = { name: key.privateKey.algorithm.name, hash: { name: hash } };
                        webcrypto.subtle.sign(alg, key.privateKey, TEST_MESSAGE)
                            .then(sig => {
                                assert.equal(!!sig, true, "Has no signature value");
                                assert.notEqual(sig.length, 0, "Has empty signature value");
                                return webcrypto.subtle.verify(alg, key.publicKey, sig, TEST_MESSAGE)
                            })
                            .then(v => assert.equal(v, true, "Signature is not valid"))
                            .then(done, done);
                    });
                });
            });
    });

    context("Derive key", () => {

        keys.filter(key => key.usages.some(usage => usage === "deriveKey"))
            .forEach(key => {
                // AES alg
                ["AES-CBC", "AES-GCM"].forEach(aesAlg => {
                    // AES length
                    [128, 192, 256].forEach(aesLength => {
                        it(`${aesAlg}-${aesLength}\t${key.name}`, done => {
                            var alg = {
                                name: key.privateKey.algorithm.name,
                                public: key.publicKey
                            };
                            webcrypto.subtle.deriveKey(alg, key.privateKey, { name: aesAlg, length: aesLength }, true, ["encrypt"])
                                .then(aesKey => {
                                    assert.equal(!!aesKey, true, "Has no derived key");
                                    assert.equal(aesKey.algorithm.length, aesLength, "Has wrong derived key length");
                                    assert.equal(aesKey.usages.length, 1, "Has wrong key usages length");
                                    assert.equal(aesKey.usages[0], "encrypt", "Has wrong key usage");
                                })
                                .then(done, done);
                        });
                    });
                });
            });
    });

    context("Derive bits", () => {

        keys.filter(key => key.usages.some(usage => usage === "deriveBits"))
            .forEach(key => {
                // length
                [56, 96, 128, 192, 256].forEach(bitsLength => {
                    it(`bits:${bitsLength} \t${key.name}`, done => {
                        var alg = {
                            name: key.privateKey.algorithm.name,
                            public: key.publicKey
                        };
                        webcrypto.subtle.deriveBits(alg, key.privateKey, bitsLength)
                            .then(bits => {
                                assert.equal(!!bits, true, "Has no derived bits");
                                assert.equal(bits.byteLength, bitsLength / 8, "Has wrong derived bits length");
                            })
                            .then(done, done);
                    });
                });
            });
    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "spki", "pkcs8", "raw"].forEach(format => {
                it(`${format}\t${key.name}`, done => {
                    var promise = Promise.resolve();
                    // Check public and private keys
                    [key.privateKey, key.publicKey].forEach(_key => {
                        if (
                            (format === "raw" && _key.type === "public") || 
                            (format === "spki" && _key.type === "public") || 
                            (format === "pkcs8" && _key.type === "private") || 
                            (format === "jwk")
                          )
                            promise = promise.then(() => {
                                return webcrypto.subtle.exportKey(format, _key)
                                    .then(jwk => {
                                        assert.equal(!!jwk, true, "Has no jwk value");
                                        if(format === "raw") {
                                          // TODO assert JWK params
                                        }
                                        return webcrypto.subtle.importKey(format, jwk, _key.algorithm, true, _key.usages);
                                    })
                            })
                                .then(k => {
                                    assert.equal(!!k, true, "Imported key is empty");
                                    checkAlgorithms(_key.algorithm, k.algorithm);
                                })
                    });
                    promise.then(done, done);
                });
            });
        });
    });

    context("Combined test", () => {
      ["jwk", "spki", "raw"].forEach(format => {
       it(`${format}\tECDH generateKey + exportKey + importKey + deriveBits`, done => {

          webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256"}, false, ["deriveKey", "deriveBits"])
          .then(function(key1){
            webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256"}, false, ["deriveKey", "deriveBits"])
            .then(function(key2){
              webcrypto.subtle.exportKey(format ,key1.publicKey)
              .then(function(keyData1){
                webcrypto.subtle.exportKey(format ,key2.publicKey)
                .then(function(keyData2){
                  webcrypto.subtle.importKey(format , keyData1, { name: "ECDH", namedCurve: "P-256" }, true, [])
                  .then(function(pub1){
                    webcrypto.subtle.importKey(format , keyData2, { name: "ECDH", namedCurve: "P-256" }, true, [])
                    .then(function(pub2){
                      webcrypto.subtle.deriveBits({ name: "ECDH", namedCurve: "P-256", public: pub1 }, key2.privateKey, 128)
                      .then(function(bits1){
                        webcrypto.subtle.deriveBits({ name: "ECDH", namedCurve: "P-256", public: pub2 }, key1.privateKey, 128)
                        .then(function(bits2){
                          assert.deepEqual(new Uint8Array(bits1), new Uint8Array(bits2), "derive Bits not equal");
                        }).then(done, done);
                      });
                    });
                  });
                });
              });
            });
          });

        });   
      });
    });

});
