const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;

describe("Crypto RSA", () => {

    var TEST_MESSAGE = Buffer.from("1234567890123456");
    var KEYS = [
        { alg: "RSASSA-PKCS1-v1_5", usages: ["sign", "verify"] },
        { alg: "RSA-PSS", usages: ["sign", "verify"] },
        { alg: "RSA-OAEP", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
    ];
    var DIGEST = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    var PUBLIC_EXPONENT = [new Uint8Array([3]), new Uint8Array([1, 0, 1])];
    var MODULUS_LENGTH = [1024, 2048, /*4096*/];

    var keys = [];

    context("Generate key", () => {

        it("Params", async () => {
            const keyPair = await webcrypto.subtle.generateKey(
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]) },
                false,
                ["sign"]
            );

            let pkey = keyPair.privateKey;
            assert.equal(pkey.type, "private");
            assert.equal(pkey.algorithm.name, "RSASSA-PKCS1-v1_5");
            assert.equal(pkey.algorithm.hash.name, "SHA-256");
            assert.equal(pkey.algorithm.modulusLength, 1024);
            assert.equal(pkey.algorithm.publicExponent.length, 3);
            assert.equal(pkey.algorithm.publicExponent[0], 1);
            assert.equal(pkey.extractable, false);

            let pubkey = keyPair.publicKey;
            assert.equal(pubkey.type, "public");
            assert.equal(pubkey.algorithm.name, "RSASSA-PKCS1-v1_5");
            assert.equal(pubkey.algorithm.hash.name, "SHA-256");
            assert.equal(pubkey.algorithm.modulusLength, 1024);
            assert.equal(pubkey.algorithm.publicExponent.length, 3);
            assert.equal(pubkey.algorithm.publicExponent[0], 1);
            assert.equal(pubkey.extractable, true);
        });

        // Keys
        KEYS.forEach(key => {
            // Digest
            DIGEST.forEach(digest => {
                // publicExponent
                PUBLIC_EXPONENT.forEach(pubExp => {
                    // modulusLength
                    MODULUS_LENGTH.forEach(modLen => {
                        const keyName = `${key.alg} ${digest} e:${pubExp.length === 1 ? 3 : 65535} n:${modLen}`
                        const algorithm = {
                            name: key.alg,
                            hash: { name: digest },
                            modulusLength: modLen,
                            publicExponent: pubExp
                        };
                        const keyTemplate = {
                            name: keyName,
                            privateKey: null,
                            publicKey: null,
                            usages: key.usages,
                            algorithm,
                        }
                        keys.push(keyTemplate);

                        it(keyName, async () => {

                            const keyPair = await webcrypto.subtle.generateKey(algorithm, true, key.usages)
                            assert.equal(!!(keyPair.privateKey || keyPair.publicKey), true, "KeyPair is empty");
                            // save  keys for next tests
                            keyTemplate.privateKey = keyPair.privateKey;
                            keyTemplate.publicKey = keyPair.publicKey;

                        }).timeout(modLen === 2048 ? 4000 : 2000);
                    });
                });
            });
        });
    });

    context("Sign/Verify", () => {

        keys.filter(key => key.usages.some(usage => usage === "sign"))
            .forEach(key => {
                it(key.name, async () => {
                    // TODO: Add label
                    const sig = await webcrypto.subtle.sign({ name: key.privateKey.algorithm.name, saltLength: 8 }, key.privateKey, TEST_MESSAGE)

                    assert.equal(!!sig, true, "Has no signature value");
                    assert.notEqual(sig.length, 0, "Has empty signature value");
                    const ok = await webcrypto.subtle.verify({ name: key.publicKey.algorithm.name, saltLength: 8 }, key.publicKey, sig, TEST_MESSAGE);

                    assert.equal(ok, true, "Signature is not valid");
                });
            });
    });

    context("Encrypt/Decrypt", () => {
        // Select keys for encrypt
        keys.filter(key => key.usages.some(usage => usage === "encrypt") &&
            !(key.algorithm.modulusLength === 1024 && // exclude RSA_padding_add_PKCS1_OAEP_mgf1:data too large for key size
                key.algorithm.hash.name === "SHA-512"))
            .forEach(key => {
                // Label
                [null, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])].forEach(label => {
                    it(`${label ? "label\t" : "no label"}\t${key.name}`, async () => {
                        const enc = await webcrypto.subtle.encrypt({ name: key.privateKey.algorithm.name, label: label }, key.publicKey, TEST_MESSAGE)
                        assert.equal(!!enc, true, "Has no encrypted value");
                        assert.notEqual(enc.length, 0, "Has empty encrypted value");

                        const dec = await webcrypto.subtle.decrypt({ name: key.publicKey.algorithm.name, label: label }, key.privateKey, enc);
                        assert.equal(Buffer.from(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is not valid")
                    });
                });
            });
    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "spki", "pkcs8"].forEach(format => {
                it(`${format}\t${key.name}`, async () => {
                    let testKey = format === "spki" ? key.publicKey : key.privateKey
                    const jwk = await webcrypto.subtle.exportKey(format, testKey);
                    assert.equal(!!jwk, true, "Has no jwk value");
                    // TODO assert JWK params
                    const k = await webcrypto.subtle.importKey(format, jwk, testKey.algorithm, true, testKey.usages);
                    assert.equal(!!k, true, "Imported key is empty");
                    checkAlgorithms(testKey.algorithm, k.algorithm);
                });
            });
        });
    });

    context("Wrap/Unwrap", () => {

        var aesKeys = [{}, {}, {}];

        before(done => {
            var promise = Promise.resolve();
            [128, 192, 256].forEach((length, index) => {
                var keyTemplate = aesKeys[index];
                promise = promise.then(() => {
                    return webcrypto.subtle.generateKey({ name: "AES-CBC", length: length }, true, ["encrypt", "decrypt"])
                        .then(key => {
                            keyTemplate.key = key;
                            // return Promise.resolve();
                        });
                });
            });
            promise.then(done, done);
        });

        // Keys
        keys.filter(key => key.usages.some(usage => "wrapKey" === usage) &&
            !(key.algorithm.modulusLength === 1024 && // exclude RSA_padding_add_PKCS1_OAEP_mgf1:data too large for key size
                (key.algorithm.hash.name === "SHA-384" ||
                    key.algorithm.hash.name === "SHA-512"
                )))
            .forEach(key => {
                // AES keys
                aesKeys.forEach(aes => {
                    // Format
                    ["raw"].forEach(format => {
                        [null, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])].forEach(label => {
                            it(`${label ? "label\t" : "no label"}\t${key.name}`, async () => {
                                var _alg = { name: key.publicKey.algorithm.name, label: label };
                                const enc = await webcrypto.subtle.wrapKey(format, aes.key, key.publicKey, _alg)
                                assert.equal(!!enc, true, "Has no encrypted value");

                                const unwrappedKey = await webcrypto.subtle.unwrapKey(format, enc, key.privateKey, _alg, aes.key.algorithm, true, aes.key.usages);
                                assert.equal(!!unwrappedKey, true, "Has no unwrapped key");
                            });
                        });
                    });
                });
            });
    });

    context("Algorithm parameters", () => {

        it("modulusLength/publicExponent for imported key", async () => {
            const keyPair = await webcrypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 }, true, ["sign", "verify"]);
            const key = keyPair.privateKey;
            assert.equal(ArrayBuffer.isView(key.algorithm.publicExponent), true);
            assert.equal(key.algorithm.publicExponent.length === 3, true);
            assert.equal(key.algorithm.modulusLength === 2048, true);
            assert.equal(key.type === "private", true);

            const raw = await webcrypto.subtle.exportKey("pkcs8", key);
            
            const key2 = await webcrypto.subtle.importKey("pkcs8", raw, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
            assert.equal(ArrayBuffer.isView(key.algorithm.publicExponent), true);
            assert.equal(key2.algorithm.publicExponent.length === 3, true);
            assert.equal(key2.algorithm.modulusLength === 2048, true);
            assert.equal(key2.type === "private", true);
        });

    });

});