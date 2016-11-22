"use strict";
var assert = require('assert');
var native = require("../buildjs/native");

describe("native", function () {

    var TEST_MESSAGE = new Buffer("Hello world");
    var TEST_MESSAGE_WRONG = new Buffer("Hello world!!!");

    context("HMAC", () => {

        let keys = [];

        [0, 128, 256, 512].forEach((length, index) => {
            let hmac = {
                length: length,
                key: null
            }
            if (length)
                keys.push(hmac)
            it(`generate length:${length}`, done => {
                native.HmacKey.generate(length, (err, data) => {
                    assert.equal(!!err, !length, err);
                    assert.equal(!!data, !!length, "Data is empty");
                    if (length)
                        hmac.key = data;
                    done();
                });
            });
        });

        context("export/import", () => {
            keys.forEach(hmac => {
                it(`length:${hmac.length}`, done => {
                    hmac.key.export((err, data) => {
                        assert.equal(!!data, true);
                        assert.equal(data.length * 8, hmac.length);
                        native.HmacKey.import(data, (err, key) => {
                            assert.equal(!!data, true);
                            key.export((err, data2) => {
                                assert.equal(!!data2, true);
                                assert.equal(data2.length * 8, hmac.length);
                                assert.equal(data2.toString("hex"), data.toString("hex"));
                                done();
                            });
                        });
                    });
                });

            });
        });

        context("sign/verify", () => {
            keys.forEach(hmac => {
                it(`length:${hmac.length}`, done => {
                    hmac.key.sign("sha1", TEST_MESSAGE, (err, signature1) => {
                        assert.equal(!!err, false, err);
                        assert.equal(signature1.length > 0, true);
                        hmac.key.verify("sha1", TEST_MESSAGE, signature1, (err, res) => {
                            assert.equal(!!err, false, err);
                            assert.equal(res, true);
                            hmac.key.verify("sha1", TEST_MESSAGE_WRONG, signature1, (err, res) => {
                                assert.equal(!!err, false, err);
                                assert.equal(res, false);
                                done();
                            });
                        });
                    });
                });
            });
        });

    });

});