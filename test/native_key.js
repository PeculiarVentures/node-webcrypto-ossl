var assert = require('assert');
var nodessl = require("../buildjs/native_key")
var crypto = require("crypto");

var fs = require("fs");

fs.readlink

//console.log(crypto.getHashes());

describe("Key", function () {

    it("New instance", function () {
        new nodessl.Key();
    })

    it("Generate Rsa key", function (done) {
        nodessl.KeyPair.generateRsa(1024, nodessl.RsaPublicExponent.RSA_3, done);
    })

    it("AES", function(){
        var aes = crypto.randomBytes(256/8);
        var iv = crypto.randomBytes(12);
        
        //console.log(crypto.getCiphers());
        var cipher = crypto.createCipheriv("aes-256-gcm", aes, iv);
        var buf = cipher.update(new Buffer("Hello world"));
        buf = Buffer.concat([buf, cipher.final()]);
        var tag = cipher.getAuthTag();
        
        var decipher = crypto.createDecipheriv("aes-256-gcm", aes, iv);
        decipher.setAuthTag(tag);
        var msg = decipher.update(buf.toString("hex"), "hex", "utf8");
        msg += decipher.final("utf8");
    })

})