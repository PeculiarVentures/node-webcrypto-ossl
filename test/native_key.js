var assert = require('assert');
var nodessl = require("../buildjs/nodessl").nodessl
var crypto = require("crypto");

//console.log(crypto.getHashes());

describe("Key", function () {

    it("New instance", function () {
        new nodessl.Key();
    })

    it("Generate Rsa key", function () {
        var key = nodessl.Key.generateRsa(1024, 1);    
        console.log("Rsa type:", key.type);    
        console.log("JWK private:", key.exportJwk("private"));    
        console.log("JWK public:", key.exportJwk("public"));    
    })
    
    it("Generate Ec key", function () {
        var key = nodessl.Key.generateEc("secp192k1");    
        console.log("Ec type:", key.type);    
        console.log("JWK private:", key.exportJwk("private"));    
        console.log("JWK public:", key.exportJwk("public"));    
    })

    it("Sign", function () {
        var key = nodessl.Key.generateRsa(2048, 1);
        var data = new Buffer("Hello world");
        var sig = nodessl.sign(key, data, "sha512");
        assert.equal(nodessl.verify(key, data, sig, "sha512"), true, "Error on verify with SHA512");
    })

    it("RSA write PKCS8 no encrypt", function () {
        var key = nodessl.Key.generateRsa(1024, 1);
        assert.equal(key.writePkcs8("pem").toString().substr(0, 5), "-----");
        assert.equal(key.writePkcs8("der")[0], 48);
    })

    it("RSA write PKCS8 crypt", function () {
        var key = nodessl.Key.generateRsa(1024, 1);
        console.log(key.writePkcs8(
            "pem",
            "psw",
            new Buffer("salt"),
            1000
            ).toString());
    })

    it("RSA write SPKI", function () {
        var key = nodessl.Key.generateRsa(1024, 1);
        assert.equal(key.writeSpki("pem").toString().substr(0, 5), "-----");
        assert.equal(key.writeSpki("der")[0], 48);
    })

    it("RSA OAEP encrypt/decrypt", function () {
        var key = nodessl.Key.generateRsa(2048, 1);
        var data = new Buffer("1234567890123456789012345678901212345678901234567890123456789012");
        var hash = "SHA1";


        var dec = key.encryptRsaOAEP(data, hash);
        var msg = key.decryptRsaOAEP(dec, hash);
        assert.equal(msg.toString(), data.toString());

        assert.throws(
            function () {
                key.decryptRsaOAEP(dec, "SHA256");
            },
            Error);
            
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