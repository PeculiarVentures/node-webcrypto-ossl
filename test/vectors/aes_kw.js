"use strict";

const assert = require('assert');
const crypto = require('../config');

let subtle = crypto.subtle;

const vectors = [
    { "algorithm": { "name": "AES-KW", "length": 128 }, "key": { "alg": "A128KW", "ext": true, "k": "7VztW2VAIOEw8ppK-ri4XQ", "key_ops": ["wrapKey", "unwrapKey"], "kty": "oct" }, "wrappedKey": "cYy3JTFpcHn93ulowQlMeW3HB9H71w1/" },
    { "algorithm": { "name": "AES-KW", "length": 256 }, "key": { "alg": "A256KW", "ext": true, "k": "HKbFtGHXDt9IhtbY-NWgMJGCK3wLNKxb_5BXjAibT44", "key_ops": ["wrapKey", "unwrapKey"], "kty": "oct" }, "wrappedKey": "6EqFFsbyZyO2arJtuN4PD72a2M/LSykCk3nYWpagObyNqiK05gZwnw==" }
];

context("Vectors", () => {

    context("AES-KW", () => {

        vectors.forEach(vector => {
            it(`length:${vector.algorithm.length}`, done => {
                subtle.importKey("jwk", vector.key, vector.algorithm, true, ["unwrapKey"])
                    .then(key => {
                        assert.equal(!!key, true, "Imported key is empty");
                        assert.equal(key.extractable, true);
                        assert.equal(key.type, "secret");
                        assert.equal(key.algorithm.name, "AES-KW");
                        assert.equal(key.algorithm.length, vector.algorithm.length);
                        assert.equal(key.usages.length, 1);
                        assert.equal(key.usages[0], "unwrapKey");

                        const wrappedKey = Buffer.from(vector.wrappedKey, "base64");
                        return subtle.unwrapKey("raw", wrappedKey, key, { name: "AES-KW" }, vector.algorithm, true, ["wrapKey"])
                    })
                    .then(key => {
                        assert.equal(!!key, true, "Imported key is empty");
                        assert.equal(key.extractable, true);
                        assert.equal(key.type, "secret");
                        assert.equal(key.algorithm.name, "AES-KW");
                        assert.equal(key.algorithm.length, vector.algorithm.length);
                        assert.equal(key.usages.length, 1);
                        assert.equal(key.usages[0], "wrapKey");

                        return subtle.exportKey("jwk", key)
                    })
                    .then(jwk => {
                        assert.equal(!!jwk, true);
                        assert.equal(jwk.alg, `A${vector.algorithm.length}KW`);
                        assert.equal(jwk.k, vector.key.k);
                    })
                    .then(done, done);
            });
        });

    });

});