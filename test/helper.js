"use strict"
const assert = require("assert");

function checkAlgorithms(alg1, alg2) {
    assert.equal(!!alg2, true, "Empty CryptoKey algorithm");
    for (let i in alg1) {
        if (ArrayBuffer.isView(alg1[i]))
            checkBuffers(alg1[i], alg2[i]);
        else
            assert.equal(alg1[i], alg2[i]);
    }
}
exports.checkAlgorithms = checkAlgorithms;

function checkBuffers(buf1, buf2) {
    let _buf1 = new Uint8Array(buf1);
    let _buf2 = new Uint8Array(buf2);

    assert.equal(_buf1.length, _buf2.length);
    // ceck values
    _buf1.forEach((v, i) => {
        assert.equal(v, _buf2[i], "Buffers have different values");
    });
}
exports.checkBuffers = checkBuffers;