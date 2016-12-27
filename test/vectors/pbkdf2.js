"use strict";

const assert = require('assert');
const crypto = require('../config');

let subtle = crypto.subtle;

const vectors = [
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-1" }, "password": "", "derivedBits": "MZjBCKYUvm9T9Ux3/5HgHw==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-256" }, "password": "", "derivedBits": "GlOzGKZYUz1EYCdJtZeRXg==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-384" }, "password": "", "derivedBits": "CdVn/cAjFqdLrCV+dz/LpA==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-512" }, "password": "", "derivedBits": "WGqAJBM7TF6Sn+Am3+6RoA==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-1" }, "password": "password", "derivedBits": "yvcSWNZgau4mEfezNj+rtg==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-256" }, "password": "password", "derivedBits": "Sj4bTP75DW4A/IN08TwLDg==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-384" }, "password": "password", "derivedBits": "n4dQaniQ+UlRohiDSL3dKQ==" },
    { "algorithm": { "name": "PBKDF2", "hash": "SHA-512" }, "password": "password", "derivedBits": "jTNIFwT5oHTGb2G2b6gJ8w==" }
];

context("PBKDF2", () => {

    vectors.forEach(vector => {
        it(`password:${vector.password || "empty"} hash:${vector.algorithm.hash}`, done => {
            const raw = new Buffer(vector.password);
            subtle.importKey("raw", raw, vector.algorithm, false, ["deriveBits"])
                .then((key) => {
                    return crypto.subtle.deriveBits(
                        { name: "PBKDF2", salt: new Uint8Array([1, 2, 3, 4, 5]), iterations: 1000, hash: vector.algorithm.hash },
                        key, 128)
                })
                .then(dBits => {
                    assert.equal(!!dBits, true);
                    assert.equal(dBits instanceof ArrayBuffer, true);
                    assert.equal(dBits.byteLength, 128 / 8);
                    assert.equal(new Buffer(dBits).toString("base64"), vector.derivedBits);
                })
                .then(done, done);
        });
    });

});