"use strict";

const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;
const subtle = webcrypto.subtle;

context("WebCrypto", () => {

    context("import", () => {
        ["", "password"].forEach(psw => {
            it(`value: ${psw || "empty"}`, done => {
                webcrypto.subtle.importKey("raw", Buffer.from(psw), "pbkdf2", false, ["deriveBits"])
                    .then(key => {
                        assert.equal(!!key, true);
                        assert.equal(!!key.algorithm, true);
                        assert.equal(key.algorithm.name, "PBKDF2");
                        assert.equal(key.algorithm.length, psw.length * 8);
                        assert.equal(key.extractable, false);
                        assert.equal(key.type, "secret");
                        assert.equal(key.usages.length, 1);
                        assert.equal(key.usages[0], "deriveBits");
                    })
                    .then(done, done)
            });
        });
    });

    context("deriveBits", () => {
        [8, 16, 128, 256, 512].forEach(length => {
            it(`length:${length}`, done => {
                webcrypto.subtle.importKey("raw", Buffer.from("password"), "pbkdf2", false, ["deriveBits"])
                    .then(key => {
                        assert.equal(!!key, true);
                        return webcrypto.subtle.deriveBits(
                            { name: "PBKDF2", salt: Buffer.from("salt"), iterations: 8, hash: "SHA-1" },
                            key,
                            length
                        );
                    })
                    .then(raw => {
                        assert.equal(raw.byteLength * 8, length)
                    })
                    .then(done, done);
            });
        });
    });

    context("deriveKey", () => {
        ["AES-CBC", "AES-GCM", "AES-KW", "HMAC"].forEach(name => {
            context(name, () => {
                [128, 192, 256].forEach(length => {
                    it(`length:${length}`, done => {
                        webcrypto.subtle.importKey("raw", Buffer.from("password"), "pbkdf2", false, ["deriveKey"])
                            .then(key => {
                                assert.equal(!!key, true);
                                return webcrypto.subtle.deriveKey(
                                    { name: "PBKDF2", salt: Buffer.from("salt"), iterations: 8, hash: "SHA-256" },
                                    key,
                                    { name, length },
                                    true,
                                    name === "HMAC" ? ["sign"] : ["wrapKey"]
                                );
                            })
                            .then(key => {
                                assert.equal(!!key, true);
                                assert.equal(key.algorithm.name, name);
                                assert.equal(key.algorithm.length, length);
                            })
                            .then(done, done);
                    });
                });
            });
        });
    });

});