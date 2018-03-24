const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;
const subtle = webcrypto.subtle;

const keys = [];
const message = Buffer.from("test message");
const message_error = Buffer.from("test message!!!");

describe("Crypto", function () {

    context("HMAC", () => {

        context("generate", () => {

            // key length
            [0, 128, 256, 512].forEach(length => {
                // hash
                ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].forEach(hash => {

                    let hmac = { key: null, name: `length:${length ? length : "default"} hash:${hash}`, length: length };
                    keys.push(hmac);

                    it(`${hmac.name}`, async () => {
                        const alg = { name: "HMAC", hash: hash };
                        if (length)
                            alg.length = length;
                        else
                            hmac.length = hash === "SHA-1" ? 160 : hash === "SHA-256" ? 256 : hash === "SHA-384" ? 384 : 512;

                        const key = await subtle.generateKey(alg, true, ["sign", "verify"]);
                        assert(!!key, true);
                        assert(!!key.native, true);
                        hmac.key = key;
                    });
                });
            });
        });

        context("export/import", () => {
            keys.forEach(hmac => {
                // format
                ["jwk", "raw"].forEach(format => {
                    it(`${hmac.name} format:${format}`, async () => {
                        const data = await subtle.exportKey(format, hmac.key);
                        switch (format) {
                            case "raw":
                                assert.equal(data.byteLength * 8, hmac.length);
                                break
                            case "jwk":
                                assert.equal(data.alg === "HS" + /(\d+)/.exec(hmac.key.algorithm.hash.name)[1], true);
                                break
                        }
                        // console.log(hmac.key);
                        const k = await subtle.importKey(format, data, hmac.key.algorithm, true, hmac.key.usages);
                        assert.equal(!!k, true);
                        assert.equal(!!k.native, true);
                        checkAlgorithms(hmac.key.algorithm, k.algorithm);
                    });
                });
            });
        });

        context("sign/verify", () => {
            keys.forEach(hmac => {
                const alg = { name: "HMAC" };

                it(hmac.name, async () => {
                    const signature = await subtle.sign(alg, hmac.key, message)
                    assert.equal(!!signature, true);

                    // Check valid signature
                    const ok = await subtle.verify(alg, hmac.key, signature, message);
                    assert.equal(ok, true);

                    // Check invalid signature
                    const wrong = await subtle.verify(alg, hmac.key, signature, message_error);
                    assert.equal(wrong, false);
                });

            });
        });

    }); // HMAC

}); // WebCrypto