const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;
const subtle = webcrypto.subtle;

context("Crypto", () => {

    context("import", () => {
        ["", "password"].forEach(psw => {
            it(`value: ${psw || "empty"}`, async () => {
                const key = await webcrypto.subtle.importKey("raw", Buffer.from(psw), "pbkdf2", false, ["deriveBits"])

                assert.equal(!!key, true);
                assert.equal(!!key.algorithm, true);
                assert.equal(key.algorithm.name, "PBKDF2");
                assert.equal(key.algorithm.length, psw.length * 8);
                assert.equal(key.extractable, false);
                assert.equal(key.type, "secret");
                assert.equal(key.usages.length, 1);
                assert.equal(key.usages[0], "deriveBits");
            });
        });
    });

    context("deriveBits", () => {
        [8, 16, 128, 256, 512].forEach(length => {
            it(`length:${length}`, async () => {
                const key = await webcrypto.subtle.importKey("raw", Buffer.from("password"), "pbkdf2", false, ["deriveBits"])

                assert.equal(!!key, true);
                const raw = await webcrypto.subtle.deriveBits(
                    { name: "PBKDF2", salt: Buffer.from("salt"), iterations: 8, hash: "SHA-256" },
                    key,
                    length
                );

                assert.equal(raw.byteLength * 8, length)

            });
        });
    });

    context("deriveKey", () => {
        ["AES-CBC", "AES-GCM", "AES-KW", "HMAC"].forEach(name => {
            context(name, () => {
                [128, 192, 256].forEach(length => {
                    it(`length:${length}`, async () => {
                        const key = await webcrypto.subtle.importKey("raw", Buffer.from("password"), "pbkdf2", false, ["deriveKey"])

                        assert.equal(!!key, true);
                        const derivedKey = await webcrypto.subtle.deriveKey(
                            { name: "PBKDF2", salt: Buffer.from("salt"), iterations: 8, hash: "SHA-256" },
                            key,
                            { name, length },
                            true,
                            name === "HMAC" ? ["sign"] : ["wrapKey"]
                        );

                        assert.equal(!!derivedKey, true);
                        assert.equal(derivedKey.algorithm.name, name);
                        assert.equal(derivedKey.algorithm.length, length);
                    });
                });
            });
        });
    });

});