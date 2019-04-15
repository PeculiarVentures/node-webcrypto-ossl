"use strict";
const assert = require('assert');
const webcrypto = require('./config');
const checkAlgorithms = require('./helper').checkAlgorithms;
const subtle = webcrypto.subtle;

const keys = [];
const message = Buffer.from("test message");
const message_error = Buffer.from("test message!!!");

describe("WebCrypto", function () {

    context("HMAC", () => {

        context("generate", () => {

            // key length
            [0, 128, 256, 512].forEach(length => {
                // hash
                ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].forEach(hash => {

                    let hmac = { key: null, name: `length:${length ? length : "default"} hash:${hash}`, length: length };
                    keys.push(hmac);

                    it(`${hmac.name}`, done => {
                        const alg = { name: "HMAC", hash: hash };
                        if (length)
                            alg.length = length;
                        else
                            hmac.length = hash === "SHA-1" ? 160 : hash === "SHA-256" ? 256 : hash === "SHA-384" ? 384 : 512;

                        subtle.generateKey(alg, true, ["sign", "verify"])
                            .then(key => {
                                assert(!!key, true);
                                assert(!!key.native, true);
                                hmac.key = key;
                            })
                            .then(done, done);
                    });
                });
            });

        });

        context("export/import", () => {
            keys.forEach(hmac => {
                // format
                ["jwk", "raw"].forEach(format => {
                    it(`${hmac.name} format:${format}`, done => {
                        subtle.exportKey(format, hmac.key)
                            .then(data => {
                                switch (format) {
                                    case "raw":
                                        assert.equal(data.byteLength * 8, hmac.length);
                                        break
                                    case "jwk":
                                        assert.equal(data.alg === "HS" + /(\d+)/.exec(hmac.key.algorithm.hash.name)[1], true);
                                        break
                                }
                                // console.log(hmac.key);
                                return subtle.importKey(format, data, hmac.key.algorithm, true, hmac.key.usages)
                            })
                            .then(k => {
                                assert.equal(!!k, true);
                                assert.equal(!!k.native, true);
                                checkAlgorithms(hmac.key.algorithm, k.algorithm);
                                done();
                            })
                            .catch(done);
                    });
                });
            });
        });

        context("sign/verify", () => {
            keys.forEach(hmac => {
                const alg = { name: "HMAC" };

                it(hmac.name, done => {
                    let sig;
                    subtle.sign(alg, hmac.key, message)
                        .then(signature => {
                            assert.equal(!!signature, true);
                            sig = signature;
                            return subtle.verify(alg, hmac.key, signature, message)
                        })
                        .then(res => {
                            assert.equal(res, true);
                            return subtle.verify(alg, hmac.key, sig, message_error)
                        })
                        .then(res => {
                            assert.equal(res, false);
                            done();
                        })
                        .catch(done);

                });

            });
        });

    }); // HMAC

}); // WebCrypto