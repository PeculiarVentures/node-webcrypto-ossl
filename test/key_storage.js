"use strict";

var assert = require("assert");
var fs = require("fs");
var webcrypto = require("./config");

var deleteFolderRecursive = function (path) {
    if (fs.existsSync(path)) {
        fs.readdirSync(path).forEach(function (file, index) {
            var curPath = path + "/" + file;
            if (fs.lstatSync(curPath).isDirectory()) { // recursion
                deleteFolderRecursive(curPath);
            } else { // delete file
                fs.unlinkSync(curPath);
            }
        });
        fs.rmdirSync(path);
    }
};

describe("Key storage", function () {

    var TEST_MESSAGE = Buffer.from("This is test message for crypto functions");
    var KEYS = [{ name: "private" }, { name: "public" }, { name: "secret" }];

    before((done) => {
        // Generate keys for storeKey
        webcrypto.subtle.generateKey({
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {
                name: "SHA-1"
            },
        },
            true,
            ["sign", "verify"]
        )
            .then((keyPair) => {
                KEYS[0].key = keyPair.privateKey;
                KEYS[1].key = keyPair.publicKey;

                return webcrypto.subtle.generateKey({
                    name: "AES-CBC",
                    length: 128,
                },
                    true,
                    ["encrypt", "decrypt"]
                )
            })
            .then((key) => {
                KEYS[2].key = key;
            })
            .then(done, done);
    });

    after(function () {
        deleteFolderRecursive("test_storage");
    })

    KEYS.forEach(key => {
        it(`Set/get key from storage ${key.name}`, () => {
            if (key.name === "secret")
                return console.log(`Not implemented test`);
            webcrypto.keyStorage.setItem(key.key.type, key.key);
            var exists = fs.existsSync(webcrypto.keyStorage.directory + `/${key.key.type}.json`);
            assert.equal(exists, true, "File with key is not created");

            var storeKey = webcrypto.keyStorage.getItem(key.key.type);
        })
    });

    it("Set secret key", () => {
        const key = { type: "secret" };
        assert.throws(() => {
            webcrypto.keyStorage.setItem("secret_key", key)
        });
    });

    it("Set unknown key type", () => {
        const key = { type: "wrong type" };
        assert.throws(() => {
            webcrypto.keyStorage.setItem("secret_key", key)
        });
    })

    it("Get non-existent item, must be null", () => {
        assert.equal(webcrypto.keyStorage.getItem("null"), null);
    })

    it("read storage from folder", () => {
        let WebCrypto = require("../buildjs/webcrypto");
        let crypto = new WebCrypto({ directory: "test_storage" });
        assert.equal(crypto.keyStorage.length, 2);
    });

    it("Remove key from storage", function (done) {
        var key = null;
        webcrypto.subtle.generateKey({
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {
                name: "SHA-1"
            },
        },
            true,
            ["sign", "verify"]
        )
            .then(function (keyPair) {
                webcrypto.keyStorage.setItem("remove_key", keyPair.privateKey);
                var exists = fs.existsSync(webcrypto.keyStorage.directory + "/remove_key.json");
                assert.equal(exists, true, "File with key is not created");
                assert.equal(webcrypto.keyStorage.length, 3);

                webcrypto.keyStorage.removeItem("remove_key");
                var exists = fs.existsSync(webcrypto.keyStorage.directory + "/remove_key.json");
                assert.equal(exists, false, "File with key is not removed");
                assert.equal(webcrypto.keyStorage.length, 2);
                return Promise.resolve();
            })
            .then(done, done);
    });

    it("Clear key storage", function () {
        webcrypto.keyStorage.clear();
        assert.equal(webcrypto.keyStorage.length, 0);
    });
});