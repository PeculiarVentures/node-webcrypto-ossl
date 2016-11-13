/// <reference path="../index.d.ts" />

import WebCrypto = require("node-webcrypto-ossl");

// Webcrypto constructor
let crypto = new WebCrypto();
crypto = new WebCrypto({});
crypto = new WebCrypto({ directory: "keystorage" });

// Webcrypto getRandomValues 
crypto.getRandomValues(new Buffer(16));
crypto.getRandomValues(new Uint8Array(16));
crypto.getRandomValues(new Uint8Array(16).buffer);

// Webcrypto Storage
let key: NodeWebcryptoOpenSSL.CryptoKey;
key = crypto.keyStorage.getItem("keyname");
crypto.keyStorage.length === 0;
crypto.keyStorage.removeItem("keyname");
crypto.keyStorage.setItem("newname", key);
crypto.keyStorage.clear();


// Webcrypto Subtle
// - diget
crypto.subtle.digest("SHA-1", new Buffer("text"))
    .then(digest =>
        console.log(new Buffer(digest).toString("hex"))
    );
// - generateKey
crypto.subtle.generateKey({ name: "AES-CBC", length: 128 }, true, ["encrypt"])
    .then(aesKey =>
        key = aesKey
    );
crypto.subtle.generateKey({ name: "RSA-OAEP", hash: "SHA-1", modulusLength: 1024, publicExponent: new Buffer([3]) }, true, ["encrypt"])
    .then(keys =>
        key = keys.privateKey
    );
// - sign/verify
crypto.subtle.sign({ name: "RSA-PSS", saltLength: 128 }, key, new Buffer("text"))
    .then(signature =>
        crypto.subtle.verify({ name: "RSA-PSS", saltLength: 128 }, key, signature, new Buffer("text"))
    )
    .then(res =>
        res === true
    );
// - encrypt/decrypt
crypto.subtle.encrypt({ name: "AES-CBC", iv: new Buffer(16) }, key, new Buffer("text"))
    .then(enc =>
        crypto.subtle.decrypt({ name: "AES-CBC", iv: new Buffer(16) }, key, new Buffer("text"))
    )
    .then(dec =>
        new Buffer(dec).toString()
    );

// native
(key.native as NodeWebcryptoOpenSSL.AesKey).decryptGcm(new Buffer(16), new Buffer("text"), new Buffer(0), 2, (err, data) => {
    err.message;
    data.readInt16BE(0);
});
(key.native as NodeWebcryptoOpenSSL.Key).sign("sha1", new Buffer("text"), (err, data) => {
    err.message;
    data.readInt16BE(0);
});