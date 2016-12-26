"use strict";

var assert = require('assert');
var native = require("../../buildjs/native");

describe("native", () => {

    context("importKey", () => {

        [0, 8, 16, 32, 33].forEach(length => {
            it(`raw length:${length}`, done => {
                native.Pbkdf2Key.importKey(new Buffer(length), (err, key) => {
                    assert.equal(!err, true);
                    assert.equal(!!key, true);
                    assert.equal(key instanceof native.Pbkdf2Key, true);
                    done();
                });
            });
        });

    });

    context("deriveBits", () => {

        ["sha1", "sha256", "sha384", "sha512"].forEach(hash => {
            it(hash, done => {
                native.Pbkdf2Key.importKey(new Buffer("123456"), (err, key) => {
                    assert.equal(!err, true);
                    key.deriveBits(hash, new Buffer("salt"), 8, 128, (err, bits) => {
                        assert.equal(!err, true);
                        assert.equal(!!bits, true);
                        assert.equal(bits.byteLength, 16);
                        done()
                    });
                });
            });
        });

        it("Wrong hash", done => {
            native.Pbkdf2Key.importKey(new Buffer("123456"), (err, key) => {
                assert.equal(!err, true);
                key.deriveBits("wrong", new Buffer("salt"), 8, 128, (err, bits) => {
                    assert.equal(!err, false);
                    done()
                });
            });
        });

        it("Iterations 0", done => {
            native.Pbkdf2Key.importKey(new Buffer("123456"), (err, key) => {
                assert.equal(!err, true);
                key.deriveBits("sha1", new Buffer("salt"), 0, 128, (err, bits) => {
                    assert.equal(!err, false);
                    done()
                });
            });
        });

        it("Bits length 0", done => {
            native.Pbkdf2Key.importKey(new Buffer("123456"), (err, key) => {
                assert.equal(!err, true);
                key.deriveBits("sha1", new Buffer("salt"), 8, 0, (err, bits) => {
                    assert.equal(!err, false);
                    done()
                });
            });
        });

    });
});