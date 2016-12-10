const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;

var keys = [];

describe("WebCrypto Aes", function () {

    var TEST_MESSAGE = new Buffer("1234567890123456");
    var KEYS = [
        { alg: "AES-CBC", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-GCM", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
    ];

    context("Generate key", () => {

        // Algs
        KEYS.forEach(key => {
            // length
            [128, 192, 256].forEach(length => {
                var keyName = `${key.alg} l:${length}`;
                var keyTemplate = {
                    name: keyName,
                    key: null,
                    usages: key.usages,
                };
                keys.push(keyTemplate);
                it(keyName, done => {
                    var alg = {
                        name: key.alg,
                        length: length
                    };
                    webcrypto.subtle.generateKey(alg, true, key.usages)
                        .then(aesKey => {
                            assert.equal(!!aesKey, true, "Aes key is empty");
                            keyTemplate.key = aesKey;
                        })
                        .then(done, done);
                });
            });
        })

    });

    context("Encrypt/Decrypt", () => {

        context("AES-CBC", () => {

            // Filter CBC
            keys.filter(key => /AES-CBC/.test(key.name))
                .forEach(key => {
                    [new Uint8Array(16), new Uint8Array(16)].forEach(iv => {
                        it(`iv:${iv.length}\t${key.name}`, done => {
                            var alg = { name: "AES-CBC", iv: iv };
                            webcrypto.subtle.encrypt(alg, key.key, TEST_MESSAGE)
                                .then(enc => {
                                    assert(!!enc, true, "Encrypted message is empty");
                                    return webcrypto.subtle.decrypt(alg, key.key, enc);
                                })
                                .then(dec => {
                                    assert(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is wrong");
                                })
                                .then(done, done);
                        });
                    });
                });
        });

        context("AES-GCM", () => {
            // Filter GCM
            keys.filter(key => /AES-GCM/.test(key.name))
                .forEach(key => {
                    // IV
                    [new Uint8Array(16)].forEach(iv => {
                        // AAD
                        [new Uint8Array([1, 2, 3, 4, 5]), null].forEach(aad => {
                            // Tag
                            [32, 64, 96, 104, 112, 120, 128].forEach(tag => {
                                it(`aad:${aad ? "+" : "-"} t:${tag}\t${key.name}`, done => {
                                    var alg = { name: "AES-GCM", iv: iv, aad: aad, tagLength: tag };
                                    webcrypto.subtle.encrypt(alg, key.key, TEST_MESSAGE)
                                        .then(enc => {
                                            assert(!!enc, true, "Encrypted message is empty");
                                            return webcrypto.subtle.decrypt(alg, key.key, enc);
                                        })
                                        .then(dec => {
                                            assert(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is wrong");
                                        })
                                        .then(done, done);
                                });
                            });
                        });
                    });
                });
        });

    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "raw"].forEach(format => {
                it(`${format}\t${key.name}`, done => {
                    webcrypto.subtle.exportKey(format, key.key)
                        .then(jwk => {
                            assert.equal(!!jwk, true, "Has no jwk value");
                            if (format === "jwk")
                                assert.equal(!!jwk.k, true, "Has no k value");
                            else
                                assert.equal(!!jwk.byteLength, true, "Wrong raw length");
                            return webcrypto.subtle.importKey(format, jwk, key.key.algorithm, true, key.key.usages);
                        })
                        .then(k => {
                            assert.equal(!!k, true, "Imported key is empty")
                            assert.equal(!!k.native_, true, "Has no native key value");
                            checkAlgorithms(key.algorithm, k.algorithm);
                        })
                        .then(done, done);
                });
            });
        });
    });

    context("Wrap/Unwrap", () => {
        context("AES-CBC", () => {
            // AES keys
            keys.filter(key => /AES-CBC/.test(key.name)).forEach(key => {
                ["jwk", "raw"].forEach(format => {
                    it(`format:${format} ${key.name}`, done => {
                        var _alg = { name: "AES-CBC", iv: new Uint8Array(16) }
                        webcrypto.subtle.wrapKey(format, key.key, key.key, _alg)
                            .then(wrappedKey => {
                                assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                                return webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                            })
                            .then(key => {
                                assert.equal(!!key, true, "Unwrapped key is empty");
                            })
                            .then(done, done);
                    })

                });
            });
        });
        context("AES-GCM", () => {
            // AES keys
            keys.filter(key => /AES-GCM/.test(key.name)).forEach(key => {
                ["jwk", "raw"].forEach(format => {
                    it(`format:${format} ${key.name}`, done => {
                        var _alg = { name: "AES-GCM", iv: new Uint8Array(16) }
                        webcrypto.subtle.wrapKey(format, key.key, key.key, _alg)
                            .then(wrappedKey => {
                                assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                                return webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                            })
                            .then(key => {
                                assert.equal(!!key, true, "Unwrapped key is empty");
                            })
                            .then(done, done);
                    })

                });
            });
        });
    });

})