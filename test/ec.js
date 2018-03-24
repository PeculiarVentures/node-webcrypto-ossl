"use strict";
const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;

describe("Crypto EC", () => {

    var TEST_MESSAGE = Buffer.from("1234567890123456");
    var KEYS = [
        { alg: "ECDSA", usages: ["sign", "verify"] },
        { alg: "ECDH", usages: ["deriveKey", "deriveBits"] },
    ];
    var DIGEST = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    var NAMED_CURVES = ["P-256", "P-384", "P-521", "K-256"];

    var keys = [];

    context("Generate key", () => {

        it("Params", async () => {
            const keyPair = await webcrypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            );
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
        });

        // Keys
        KEYS.forEach((key) => {
            // namedCurve
            NAMED_CURVES.forEach((namedCurve) => {
                var keyName = `${key.alg} crv:${namedCurve}`
                var keyTemplate = {
                    name: keyName,
                    privateKey: null,
                    publicKey: null,
                    usages: key.usages,
                }
                keys.push(keyTemplate);
                it(keyName, async () => {
                    var alg = {
                        name: key.alg,
                        namedCurve: namedCurve
                    };
                    const keyPair = await webcrypto.subtle.generateKey(alg, true, key.usages)

                    assert.equal(!!(keyPair.privateKey || keyPair.publicKey), true, "KeyPair is empty");
                    // save  keys for next tests
                    keyTemplate.privateKey = keyPair.privateKey;
                    keyTemplate.publicKey = keyPair.publicKey;

                });
            });
        });
    });

    context("Sign/Verify", () => {

        keys.filter(key => key.usages.some((usage) => usage === "sign"))
            .forEach(key => {
                // Hash
                DIGEST.forEach(hash => {
                    it(`${hash}\t${key.name}`, async () => {
                        var alg = { name: key.privateKey.algorithm.name, hash: { name: hash } };
                        const sig = await webcrypto.subtle.sign(alg, key.privateKey, TEST_MESSAGE)
                        assert.equal(!!sig, true, "Has no signature value");
                        assert.notEqual(sig.length, 0, "Has empty signature value");

                        const ok = await webcrypto.subtle.verify(alg, key.publicKey, sig, TEST_MESSAGE)
                        assert.equal(ok, true, "Signature is invalid");
                    });
                });
            });
    });

    context("Derive key", () => {

        keys.filter(key => key.usages.some((usage) => usage === "deriveKey"))
            .forEach(key => {
                // AES alg
                ["AES-CBC", "AES-GCM"].forEach((aesAlg) => {
                    // AES length
                    [128, 192, 256].forEach((aesLength) => {
                        it(`${aesAlg}-${aesLength}\t${key.name}`, async () => {
                            var alg = {
                                name: key.privateKey.algorithm.name,
                                public: key.publicKey
                            };
                            const aesKey = await webcrypto.subtle.deriveKey(alg, key.privateKey, { name: aesAlg, length: aesLength }, true, ["encrypt"])
                            assert.equal(!!aesKey, true, "Has no derived key");
                            assert.equal(aesKey.algorithm.length, aesLength, "Has wrong derived key length");
                            assert.equal(aesKey.usages.length, 1, "Has wrong key usages length");
                            assert.equal(aesKey.usages[0], "encrypt", "Has wrong key usage");
                        });
                    });
                });
            });
    });

    context("Derive bits", () => {

        keys.filter(key => key.usages.some((usage) => usage === "deriveBits"))
            .forEach(key => {
                // length
                [56, 96, 128, 192, 256].forEach(bitsLength => {
                    it(`bits:${bitsLength} \t${key.name}`, async () => {
                        var alg = {
                            name: key.privateKey.algorithm.name,
                            public: key.publicKey
                        };
                        const bits = await webcrypto.subtle.deriveBits(alg, key.privateKey, bitsLength)
                        assert.equal(!!bits, true, "Has no derived bits");
                        assert.equal(bits.byteLength, bitsLength / 8, "Has wrong derived bits length");
                    });
                });
            });
    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "spki", "pkcs8", "raw"].forEach((format) => {
                it(`${format}\t${key.name}`, async () => {
                    // Check public and private keys
                    for (const _key of [key.privateKey, key.publicKey]) {
                        if (
                            (format === "raw" && _key.type === "public") ||
                            (format === "spki" && _key.type === "public") ||
                            (format === "pkcs8" && _key.type === "private") ||
                            (format === "jwk")
                        ) {
                            const jwk = await webcrypto.subtle.exportKey(format, _key);
                            assert.equal(!!jwk, true, "Has no jwk value");

                            const k = await webcrypto.subtle.importKey(format, jwk, _key.algorithm, true, _key.usages);

                            assert.equal(!!k, true, "Imported key is empty");
                            checkAlgorithms(_key.algorithm, k.algorithm);
                        }
                    }
                });
            });
        });
    });

    context("Combined test", () => {
        ["jwk", "spki", "raw"].forEach(format => {
            it(`${format}\tECDH generateKey + exportKey + importKey + deriveBits`, async () => {
                const alg = { name: "ECDH", namedCurve: "P-256" };
                const key1 = await webcrypto.subtle.generateKey(alg, false, ["deriveKey", "deriveBits"]);
                const key2 = await webcrypto.subtle.generateKey(alg, false, ["deriveKey", "deriveBits"]);
                const keyData1 = await webcrypto.subtle.exportKey(format, key1.publicKey);
                const keyData2 = await webcrypto.subtle.exportKey(format, key2.publicKey);
                const pub1 = await webcrypto.subtle.importKey(format, keyData1, alg, true, []);
                const pub2 = await webcrypto.subtle.importKey(format, keyData2, alg, true, []);
                const bits1 = await webcrypto.subtle.deriveBits(Object.assign({}, alg, { public: pub1 }), key2.privateKey, 128);
                const bits2 = await webcrypto.subtle.deriveBits(Object.assign({}, alg, { public: pub2 }), key1.privateKey, 128);

                assert.deepEqual(new Uint8Array(bits1), new Uint8Array(bits2), "derived Bits not equal");
            });
        });
    });

});
