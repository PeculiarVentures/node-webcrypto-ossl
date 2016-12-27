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

const vectorsKey = [{ "algorithm": { "name": "PBKDF2", "hash": "SHA-1" }, "password": "", "key": { "alg": "A128CBC", "ext": true, "k": "MZjBCKYUvm9T9Ux3_5HgHw", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "PZySgqtYaAzTLv+eevqUFQ==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-256" }, "password": "", "key": { "alg": "A128CBC", "ext": true, "k": "GlOzGKZYUz1EYCdJtZeRXg", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "BOAUIe71oASqkAkEaexcew==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-384" }, "password": "", "key": { "alg": "A128CBC", "ext": true, "k": "CdVn_cAjFqdLrCV-dz_LpA", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "u1+ZPiMlJ9nsXVxeQ+Aq5w==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-512" }, "password": "", "key": { "alg": "A128CBC", "ext": true, "k": "WGqAJBM7TF6Sn-Am3-6RoA", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "Nk9mDREG3cxn1SxlsJQUIg==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-1" }, "password": "password", "key": { "alg": "A128CBC", "ext": true, "k": "yvcSWNZgau4mEfezNj-rtg", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "s9bk3ikb7xRwHFKvkBensA==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-256" }, "password": "password", "key": { "alg": "A128CBC", "ext": true, "k": "Sj4bTP75DW4A_IN08TwLDg", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "EXGntv99x28t9rI4uuYGoA==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-384" }, "password": "password", "key": { "alg": "A128CBC", "ext": true, "k": "n4dQaniQ-UlRohiDSL3dKQ", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "9QNeVgy/CmNRZ6rztCX4iQ==" }, { "algorithm": { "name": "PBKDF2", "hash": "SHA-512" }, "password": "password", "key": { "alg": "A128CBC", "ext": true, "k": "jTNIFwT5oHTGb2G2b6gJ8w", "key_ops": ["encrypt"], "kty": "oct" }, "encrypted": "NNQ94K7/yvygm2pQRKM8xw==" }];

context("PBKDF2", () => {

    context("deriveBits", () => {
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

    context("deriveKey", () => {
        vectorsKey.forEach(vector => {
            it(`AES-CBC password:${vector.password || "empty"} hash:${vector.algorithm.hash}`, done => {
                const raw = new Buffer(vector.password);
                let aes;
                subtle.importKey("raw", raw, vector.algorithm, false, ["deriveKey"])
                    .then((key) => {
                        return crypto.subtle.deriveKey(
                            { name: "PBKDF2", salt: new Uint8Array([1, 2, 3, 4, 5]), iterations: 1000, hash: vector.algorithm.hash },
                            key,
                            { name: "AES-CBC", length: 128 },
                            true,
                            ["encrypt"]
                        )
                    })
                    .then(aesKey => {
                        aes = aesKey
                        return crypto.subtle.exportKey("jwk", aesKey);
                    })
                    .then(jwk => {
                        assert.equal(jwk.k, vector.key.k);
                        return crypto.subtle.encrypt(
                            { name: "AES-CBC", iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]) },
                            aes,
                            new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
                        )
                    })
                    .then(enc => {
                        assert.equal(!!enc, true);
                        assert.equal(enc instanceof ArrayBuffer, true);
                        assert.equal(new Buffer(enc).toString("base64"), vector.encrypted);
                    })
                    .then(done, done);
            });
        });
    })

});