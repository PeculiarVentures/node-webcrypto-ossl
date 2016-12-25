"use strict";
var assert = require('assert');
var webcrypto = require('./config');

describe("WebCrypto digest", function () {

    var TEST_MESSAGE = new Buffer("12345678901234561234567890123456");

    context("Sha", function () {

        ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].forEach(digestAlg =>
            it(`Valid digest ${digestAlg}`, done => {
                webcrypto.subtle.digest({ name: digestAlg }, TEST_MESSAGE)
                    .then(function (k) {
                        assert.equal(k.key !== null, true, "Digest is empty");
                        return Promise.resolve();
                    })
                    .then(done, done);
            }));

    });

})