var assert = require('assert');

describe("RSA", function () {
    var webcrypto;
    var keys;
    
    var TEST_MESSAGE = new Buffer("This is test message for crypto functions");

    before(function(done){
        webcrypto = global.webcrypto;
        keys = global.keys;
      
        done();
    })

    it("RSA PKCS1 1.5 sign/verify", function (done) {
        var key = null;
		webcrypto.subtle.generateKey({
            name:"RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["sign", "verify"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, key.privateKey, TEST_MESSAGE) 
        })
        .then(function(sig){
            assert.equal(sig !== null, true, "Has no signature value");
            assert.notEqual(sig.length, 0, "Has empty signature value");
            return webcrypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, key.publicKey, sig, TEST_MESSAGE)
        })
        .then(function(v){
            assert.equal(v, true, "Rsa PKCS1 signature is not valid")
        })
        .then(done, done);
    })
    
    it("RSA PKCS1 export/import JWK", function (done) {
        var key = null;
        var _jwk;
		webcrypto.subtle.generateKey({
            name:"RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([3]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["sign", "verify"]
        )
        .then(function(k){
            assert.equal(k.privateKey != null, true, "Has no private key");
            assert.equal(k.publicKey != null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.exportKey("jwk", key.publicKey)  
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK publicKey");
            return webcrypto.subtle.importKey(
                "jwk",
                jwk,
                {
                    name:"RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "SHA-1"
                    } 
                },
                false,
                ["verify"]
            ); 
        })
        .then(function(k){
            assert.equal(k.type === "public", true, "Key is not Public");
            assert.equal(k.algorithm.name === "RSASSA-PKCS1-v1_5", true, "Key is not RSASSA-PKCS1-v1_5");
            return webcrypto.subtle.exportKey("jwk", key.privateKey)
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK privateKey");
            assert.equal(jwk.e !== null, true, "Wrong JWK key param");
            assert.equal(jwk.n !== null, true, "Wrong JWK key param");
            assert.equal(jwk.d !== null, true, "Wrong JWK key param");
            assert.equal(jwk.p !== null, true, "Wrong JWK key param");
            assert.equal(jwk.q !== null, true, "Wrong JWK key param");
            assert.equal(jwk.dp !== null, true, "Wrong JWK key param");
            assert.equal(jwk.dq !== null, true, "Wrong JWK key param");
            assert.equal(jwk.qi !== null, true, "Wrong JWK key param");
            assert.equal(jwk.alg !== null, true, "Wrong JWK key param");
            assert.equal(jwk.key_ops !== null, true, "Wrong JWK key param");
            _jwk = jwk;
            return webcrypto.subtle.importKey(
                "jwk", 
                jwk,
                {
                    name:"RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "SHA-1"
                    } 
                },
                true,
                ["sign"]
                );
        })
        .then(function(k){
            assert.equal(k.type === "private", true, "Key is not Private");
            assert.equal(k.algorithm.name === "RSASSA-PKCS1-v1_5", true, "Key is not RSASSA-PKCS1-v1_5");
            key = k;
            return webcrypto.subtle.exportKey("jwk", k)
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK privateKey");
            assert.equal(jwk.n === _jwk.n, true, "RSA has wrong key parameter");
            assert.equal(jwk.e === _jwk.e, true, "RSA has wrong key parameter");
            assert.equal(jwk.d === _jwk.d, true, "RSA has wrong key parameter");
            assert.equal(jwk.p === _jwk.p, true, "RSA has wrong key parameter");
            assert.equal(jwk.q === _jwk.q, true, "RSA has wrong key parameter");
            assert.equal(jwk.dp === _jwk.dp, true, "RSA has wrong key parameter");
            assert.equal(jwk.dq === _jwk.dq, true, "RSA has wrong key parameter");
            assert.equal(jwk.qi === _jwk.qi, true, "RSA has wrong key parameter");
            return webcrypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, key, TEST_MESSAGE) 
        })
        .then(function(sig){
            assert.equal(sig !== null, true, "Has no signature value");
        })
        .then(done, done);
    })
    
    it("RSA OAEP export/import JWK", function (done) {
        var key = null;
        var _jwk;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-256"
            }}, 
            false, 
            ["encrypt", "decrypt"]
        )
        .then(function(k){
            assert.equal(k.privateKey != null, true, "Has no private key");
            assert.equal(k.publicKey != null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.exportKey("jwk", key.publicKey)  
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK publicKey");
            return webcrypto.subtle.importKey(
                "jwk",
                jwk,
                {
                    name:"RSA-OAEP",
                    hash: {
                        name: "SHA-256"
                    } 
                },
                false,
                ["encrypt"]
            ); 
        })
        .then(function(k){
            assert.equal(k.type === "public", true, "Key is not Public");
            assert.equal(k.algorithm.name === "RSA-OAEP", true, "Key is not RSA-OAEP");
            return webcrypto.subtle.exportKey("jwk", key.privateKey)
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK privateKey");
            _jwk = jwk;
            return webcrypto.subtle.importKey(
                "jwk", 
                jwk,
                {
                    name: "RSA-OAEP",
                    hash:{
                        name: "SHA-256"
                    }
                },
                true,
                ["decrypt"]
                );
        })
        .then(function(k){
            assert.equal(k.type === "private", true, "Key is not Private");
            assert.equal(k.algorithm.name === "RSA-OAEP", true, "Key is not RSA-OAEP");
            return webcrypto.subtle.exportKey("jwk", k)
        })
        .then(function(jwk){
            assert.equal(jwk != null, true, "Has no JWK privateKey");
            assert.equal(jwk.n === _jwk.n, true, "RSA has wrong key parameter");
            assert.equal(jwk.e === _jwk.e, true, "RSA has wrong key parameter");
            assert.equal(jwk.d === _jwk.d, true, "RSA has wrong key parameter");
            assert.equal(jwk.p === _jwk.p, true, "RSA has wrong key parameter");
            assert.equal(jwk.q === _jwk.q, true, "RSA has wrong key parameter");
            assert.equal(jwk.dp === _jwk.dp, true, "RSA has wrong key parameter");
            assert.equal(jwk.dq === _jwk.dq, true, "RSA has wrong key parameter");
            assert.equal(jwk.qi === _jwk.qi, true, "RSA has wrong key parameter");
        })
        .then(done, done);
    })
    
    it("RSA OAEP encrypt/decrypt", function (done) {
        var key = null;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["encrypt", "decrypt"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.encrypt({name: "RSA-OAEP"}, key.publicKey, TEST_MESSAGE) 
        })
        .then(function(enc){
            assert.equal(enc !== null, true, "Has no encrypted value");
            assert.notEqual(enc.length, 0, "Has empty encrypted value");
            return webcrypto.subtle.decrypt({name: "RSA-OAEP"}, key.privateKey, enc);
        })
        .then(function(dec){
            var str = "";
            var buf = new Uint8Array(dec);
            for (var i=0; i<buf.length; i++)
                str+=String.fromCharCode(buf[i]);
            assert.equal(str, TEST_MESSAGE.toString(), "Rsa OAEP encrypt/decrypt is not valid")
        })
        .then(done, done);
    })
    
    it("RSA OAEP wrap/unwrap", function (done) {
        var key = null;
        var skey = null;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["wrapKey", "unwrapKey"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            keys.push(key);
            return webcrypto.subtle.generateKey({
                name: "AES-CBC",
                length: 128, //can be  128, 192, or 256
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"]); 
        })
        .then(function(sk){
            skey = sk;
            assert.equal(skey.key !== null, true, "Has no secret key");
            return webcrypto.subtle.wrapKey(
                "raw",
                skey, 
                key.publicKey, 
                {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-1"}
                })        
        })
        .then(function(dec){
            return webcrypto.subtle.unwrapKey(
                "raw", //the import format, must be "raw" (only available sometimes)
                dec, //the key you want to unwrap
                key.privateKey, //the private key with "unwrapKey" usage flag
                {   //these are the wrapping key's algorithm options
                    name: "RSA-OAEP",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {name: "SHA-1"},
                },
                {   //this what you want the wrapped key to become (same as when wrapping)
                    name: "AES-CBC",
                    length: 128
                },
                false, //whether the key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
            )
        })
        .then(function(sk){
            assert.equal(sk.key !== null, true, "Has no secret key");
        })
        .then(done, done);
    })
    
    it("RSA OAEP encrypt/decrypt with label", function (done) {
        var key = null;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["encrypt", "decrypt"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.exportKey("jwk", k.privateKey);
        })
        .then(function(jwk){
            console.log(jwk);
            var label = webcrypto.getRandomValues(new Uint8Array(4));
            console.log("Label:", label); 
            return webcrypto.subtle.encrypt({name: "RSA-OAEP", label: label}, key.publicKey, TEST_MESSAGE) 
        })
        .then(function(enc){
            console.log("Encrypted:", new Buffer(enc).toString("base64"));
            assert.equal(enc !== null, true, "Has no encrypted value");
            assert.notEqual(enc.length, 0, "Has empty encrypted value");
            return webcrypto.subtle.decrypt({name: "RSA-OAEP"}, key.privateKey, enc);
        })
        .then(function(dec){
            var str = "";
            var buf = new Uint8Array(dec);
            for (var i=0; i<buf.length; i++)
                str+=String.fromCharCode(buf[i]);
            assert.equal(str, TEST_MESSAGE.toString(), "Rsa OAEP encrypt/decrypt is not valid")
        })
        .then(done, done);
    })
})