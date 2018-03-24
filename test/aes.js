const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;

var keys = [];

describe("Crypto Aes", function () {

    let BIG_MESSAGE;
    let i = 0;
    while (i++ < 200)
        BIG_MESSAGE += "0123456789";
    var SMALL_MESSAGE = "1234567890123456";
    let messages = [
        { name: "small", data: SMALL_MESSAGE },
        { name: "big", data: BIG_MESSAGE },
    ];
    var KEYS = [
        { alg: "AES-ECB", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-CBC", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-CTR", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-GCM", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-KW", usages: ["wrapKey", "unwrapKey"] },
    ];

    context("Generate key", () => {

        // Keys
        KEYS.forEach((key) => {
            // length
            [128, 192, 256].forEach((length) => {
                const keyName = `${key.alg} l:${length}`;
                const keyTemplate = {
                    name: keyName,
                    key: null,
                    usages: key.usages,
                };
                keys.push(keyTemplate);
                it(keyName, async () => {
                    const alg = {
                        name: key.alg,
                        length: length
                    };
                    const aesKey = await webcrypto.subtle.generateKey(alg, true, key.usages)
                    assert.equal(!!aesKey, true, "Aes key is empty");
                    keyTemplate.key = aesKey;
                });
            });
        });

    });

    context("Encrypt/Decrypt", () => {

        context("AES-ECB", () => {

            // Filter ECB
            keys.filter((key) => /AES-ECB/.test(key.name))
                .forEach((key) => {
                    messages.forEach((message) => {
                        it(`${message.name} message\t${key.name}`, async () => {
                            const alg = { name: "AES-ECB" };
                            const enc = await webcrypto.subtle.encrypt(alg, key.key, Buffer.from(message.data))
                            assert(!!enc, true, "Encrypted message is empty");

                            const dec = await webcrypto.subtle.decrypt(alg, key.key, enc);
                            assert(Buffer.from(dec).toString(), message.data, "Decrypted message is wrong");
                        });
                    })
                });
        });

        context("AES-CBC", () => {

            // Filter CBC
            keys.filter((key) => /AES-CBC/.test(key.name))
                .forEach((key) => {
                    messages.forEach((message) =>
                        [webcrypto.getRandomValues(new Uint8Array(16))].forEach(iv => {
                            it(`${message.name} message iv:${iv.length}\t${key.name}`, async () => {
                                const alg = { name: "AES-CBC", iv: iv };
                                const enc = await webcrypto.subtle.encrypt(alg, key.key, Buffer.from(message.data))
                                assert(!!enc, true, "Encrypted message is empty");

                                const dec = await webcrypto.subtle.decrypt(alg, key.key, enc);
                                assert(Buffer.from(dec).toString(), message.data, "Decrypted message is wrong");
                            });
                        })
                    )
                });
        });

        context("AES-CTR", () => {

            // Filter CBC
            keys.filter((key) => /AES-CTR/.test(key.name))
                .forEach((key) => {
                    messages.forEach((message) =>
                        [webcrypto.getRandomValues(new Uint8Array(16))].forEach(iv => {
                            it(`${message.name} message counter:${iv.length}\t${key.name}`, async () => {
                                const alg = { name: "AES-CTR", counter: iv, length: 64 };
                                const enc = await webcrypto.subtle.encrypt(alg, key.key, Buffer.from(message.data))
                                assert(!!enc, true, "Encrypted message is empty");

                                const dec = await webcrypto.subtle.decrypt(alg, key.key, enc);
                                assert(Buffer.from(dec).toString(), message.data, "Decrypted message is wrong");
                            });
                        })
                    )
                });
        });

        context("AES-GCM", () => {
            // Filter GCM
            keys.filter((key) => /AES-GCM/.test(key.name))
                .forEach((key) => {
                    messages.forEach((message) =>
                        // IV
                        [new Uint8Array(16)].forEach((iv) => {
                            // AAD
                            [new Uint8Array([1, 2, 3, 4, 5]), null].forEach((aad) => {
                                // Tag
                                [32, 64, 96, 104, 112, 120, 128].forEach((tag) => {
                                    it(`${message.name} message aad:${aad ? "+" : "-"} t:${tag}\t${key.name}`, async () => {
                                        const alg = { name: "AES-GCM", iv: iv, aad: aad, tagLength: tag };
                                        const enc = await webcrypto.subtle.encrypt(alg, key.key, Buffer.from(message.data))
                                        assert(!!enc, true, "Encrypted message is empty");

                                        const dec = await webcrypto.subtle.decrypt(alg, key.key, enc);
                                        assert(Buffer.from(dec).toString(), message.data, "Decrypted message is wrong");
                                    });
                                });
                            });
                        })
                    )
                });
        });

    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "raw"].forEach((format) => {
                it(`${format}\t${key.name}`, async () => {
                    const jwk = await webcrypto.subtle.exportKey(format, key.key);
                    assert.equal(!!jwk, true, "Has no jwk value");
                    if (format === "jwk")
                        assert.equal(!!jwk.k, true, "Has no k value");
                    else
                        assert.equal(!!jwk.byteLength, true, "Wrong raw length");

                    const k = await webcrypto.subtle.importKey(format, jwk, key.key.algorithm, true, key.key.usages);
                    assert.equal(!!k, true, "Imported key is empty")
                    assert.equal(!!k.native_, true, "Has no native key value");
                    checkAlgorithms(key.algorithm, k.algorithm);
                });
            });
        });
    });

    context("Wrap/Unwrap", () => {
        context("AES-CBC", () => {
            // AES keys
            keys.filter((key) => /AES-CBC/.test(key.name)).forEach((key) => {
                ["jwk", "raw"].forEach((format) => {
                    it(`format:${format} ${key.name}`, async () => {
                        var _alg = { name: "AES-CBC", iv: new Uint8Array(16) }
                        const wrappedKey = await webcrypto.subtle.wrapKey(format, key.key, key.key, _alg);
                        assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                        const unwrappedKey = await webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                        assert.equal(!!unwrappedKey, true, "Unwrapped key is empty");
                    });
                });
            });
        });
        context("AES-CTR", () => {
            // AES keys
            keys.filter((key) => /AES-CTR/.test(key.name)).forEach((key) => {
                ["jwk", "raw"].forEach((format) => {
                    it(`format:${format} ${key.name}`, async () => {
                        var _alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 64 }
                        const wrappedKey = await webcrypto.subtle.wrapKey(format, key.key, key.key, _alg);
                        assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                        const unwrappedKey = await webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                        assert.equal(!!unwrappedKey, true, "Unwrapped key is empty");
                    });
                });
            });
        });
        context("AES-ECB", () => {
            // AES keys
            keys.filter((key) => /AES-ECB/.test(key.name)).forEach((key) => {
                ["jwk", "raw"].forEach((format) => {
                    it(`format:${format} ${key.name}`, async () => {
                        var _alg = { name: "AES-ECB" };
                        const wrappedKey = await webcrypto.subtle.wrapKey(format, key.key, key.key, _alg)
                        assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                        const unwrappedKey = await webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                        assert.equal(!!unwrappedKey, true, "Unwrapped key is empty");
                    })

                });
            });
        });
        context("AES-GCM", () => {
            // AES keys
            keys.filter((key) => /AES-GCM/.test(key.name)).forEach((key) => {
                ["jwk", "raw"].forEach((format) => {
                    it(`format:${format} ${key.name}`, async () => {
                        var _alg = { name: "AES-GCM", iv: new Uint8Array(16) }
                        const wrappedKey = await webcrypto.subtle.wrapKey(format, key.key, key.key, _alg)
                        assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                        const unwrappedKey = await webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);

                        assert.equal(!!unwrappedKey, true, "Unwrapped key is empty");
                    });
                });
            });
        });

        context("AES-KW", () => {
            keys.filter((key) => /AES-KW/.test(key.name)).forEach((key) => {
                ["raw"].forEach((format) => {
                    it(`format:${format} ${key.name}`, async () => {
                        var _alg = { name: "AES-KW" }
                        const wrappedKey = await webcrypto.subtle.wrapKey(format, key.key, key.key, _alg)
                        assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                        const unwrappedKey = await webcrypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["wrapKey"]);
                        assert.equal(!!unwrappedKey, true, "Unwrapped key is empty");
                    });
                });
            });
        });
    });

});