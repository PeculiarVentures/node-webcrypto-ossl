"use strict";
var assert = require('assert');
var webcrypto = require('./config');

describe("WebCrypto digest", function () {

    context("Sha", function () {

        var vector = {
            data: new Uint8Array([116, 101, 115, 116]), // "test"
            algs: {
                "SHA-1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
                "SHA-256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "SHA-384": "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
                "SHA-512": "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
            }
        };

        var dataList = {
            ArrayBuffer: vector.data.buffer,
            Buffer: Buffer.from(vector.data),
            Uint8Array: vector.data,
            Uint16Array: new Uint16Array(vector.data.buffer),
            Uint32Array: new Uint32Array(vector.data.buffer),
        };

        ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].forEach(digestAlg => {
            context(digestAlg, () => {
                for (const type in dataList) {
                    (() => {
                        const data = dataList[type];

                        it(type, done => {
                            webcrypto.subtle.digest(digestAlg, data)
                                .then(function (hash) {
                                    assert.equal(Buffer.from(hash).toString("hex").toLowerCase(), vector.algs[digestAlg]);
                                })
                                .then(done, done);
                        });
                    })();
                }
            });
        });

        context("Array", () => {

            it("subarray", (done) => {
                const data = new Uint8Array([116, 101, 115, 116, 1, 2, 3, 4, 5])

                webcrypto.subtle.digest("SHA-256", data.subarray(0, 4))
                    .then(function (hash) {
                        assert.equal(Buffer.from(hash).toString("hex").toLowerCase(), vector.algs["SHA-256"]);
                    })
                    .then(done, done);
            });

            it("slice", (done) => {
                const data = new Uint8Array([116, 101, 115, 116, 1, 2, 3, 4, 5])

                webcrypto.subtle.digest("SHA-256", data.slice(0, 4))
                    .then(function (hash) {
                        assert.equal(Buffer.from(hash).toString("hex").toLowerCase(), vector.algs["SHA-256"]);
                    })
                    .then(done, done);
            });

        });

    });
});