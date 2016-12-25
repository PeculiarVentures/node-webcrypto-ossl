"use strict";
var assert = require('assert');
var native = require("../buildjs/native");

describe("native", function () {

    var TEST_MESSAGE = new Buffer("Hello world");

    function test_export(key, spki, done) {
        var export_fn, import_fn, error_text;
        if (spki) {
            export_fn = key.exportSpki;
            import_fn = native.Key.importSpki;
            error_text = "SPKI";
        }
        else {
            export_fn = key.exportPkcs8;
            import_fn = native.Key.importPkcs8;
            error_text = "PKCS8"
        }

        export_fn.call(key, function (err, rawA) {
            assert(!err, true, `${error_text}::Export: ${err}`);
            import_fn(rawA, function (err, key) {
                assert(!err, true, `${error_text}::Import: ${err}`);
                export_fn.call(key, function (err, rawB) {
                    assert(!err, true, `${error_text}::Export: ${err}`);
                    assert.equal(Buffer.compare(rawA, rawB), 0, `${error_text}::Export: export values are different`);
                    done();
                });
            })
        })
    }

    it("generate RSA 1024,3", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    it("generate RSA 2048,F4", function (done) {
        native.Key.generateRsa(2048, native.RsaPublicExponent.RSA_F4, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    }).timeout(30e3)

    it("generate RSA error", function (done) {
        native.Key.generateRsa(1024, 3, function (err, key) {
            assert(err != null, true, "Must be error on key generation");
            done();
        })
    })

    it("jwk RSA private", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportJwk(native.KeyType.PRIVATE, function (err, jwk) {
                assert(jwk != null, true, "Error on key export");
                assert.equal(jwk.kty, "RSA");
                assert.equal(jwk.d != null, true, "Key is not private");
                native.Key.importJwk(jwk, native.KeyType.PRIVATE, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    it("jwk RSA public", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.exportJwk(native.KeyType.PUBLIC, function (err, jwk) {
                assert(jwk != null, true, "Error on key export");
                assert.equal(jwk.kty, "RSA");
                assert.equal(jwk.d == null, true, "Key is private");
                native.Key.importJwk(jwk, native.KeyType.PUBLIC, function (err, key) {
                    assert(key != null, true, "Error on key import");
                    done();
                })
            })
        })
    })

    it("spki RSA", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            test_export(key, true, done);
        })
    })

    it("pksc8 RSA", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            test_export(key, false, done);
        })
    })

    function test_sign(key, md, done) {
        var message = new Buffer("This is test message for crypto functions");

        key.sign(md, message, function (err, sig) {
            assert(sig != null, true, "Error on sign");
            key.verify(md, message, sig, function (err, v) {
                assert(v, true, "Signature is not valid");
                done();
            })
        })
    }

    it("sign RSA sha1", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            assert.equal(err == null, true, "error on sign");
            test_sign(key, "sha1", done);
        });
    })

    function test_rsa_oaep_enc_dec(md, message, label, done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.RsaOaepEncDec(md, message, label, false, function (err, dec) {
                assert(dec != null, true, "Error on encrypt");
                key.RsaOaepEncDec(md, dec, label, true, function (err, msg) {
                    assert(msg != null, true, "Error on decrypt");
                    assert(Buffer.compare(msg, message) === 0, true, "Wrong result value");
                    done();
                })
            })
        })
    }

    it("encypt RSA OAEP without label", function (done) {
        test_rsa_oaep_enc_dec("sha1", new Buffer("Hello world"), null, done);
    })

    it("encypt RSA OAEP with label", function (done) {
        test_rsa_oaep_enc_dec("sha1", new Buffer("Hello world"), new Buffer("1234567890"), done);
    })

    it("generate EC secp256k1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    function test_sign_ec(curve, md, done) {
        native.Key.generateEc(native.EcNamedCurves[curve], function (err, key) {
            assert(key != null, true, "Error on key generation");
            test_sign(key, md, done);
        })
    }

    it("sign EC secp256r1 sha256", function (done) {
        test_sign_ec("secp256r1", "sha256", done);
    })

    it("sign EC secp384r1 sha256", function (done) {
        test_sign_ec("secp384r1", "sha256", done);
    })

    it("sign EC secp521r1 sha256", function (done) {
        test_sign_ec("secp521r1", "sha256", done);
    })

    function test_derive_key_ec(curve, keySize, done) {
        native.Key.generateEc(native.EcNamedCurves[curve], function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveKey(key, keySize, function (err, b) {
                assert(b != null, true, "Error on key derive");
                // console.log(b.toString("hex"));
                done();
            })
        })
    }

    it("deriveKey EC secp256r1 -> AES 256", function (done) {
        test_derive_key_ec("secp256r1", 32, done);
    })

    it("deriveKey EC secp384r1 -> AES 256", function (done) {
        test_derive_key_ec("secp384r1", 32, done);
    })

    it("deriveKey EC secp521r1 -> AES 256", function (done) {
        test_derive_key_ec("secp521r1", 32, done);
    })

    function jwk_equal(a, b) {
        var json1 = JSON.stringify(a);
        var json2 = JSON.stringify(b);
        return json1 == json2;
    }

    function test_ec_jwk(curveName, keyType, done) {

        var curve = native.EcNamedCurves[curveName]
        assert.equal(curve != null, true, "Unknown curve name");

        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            key.exportJwk(keyType, function (err, jwkA) {
                assert(!err, true, "Export: " + err);
                assert.equal(jwkA.kty, "EC", "Export: Wrong key type value");
                assert.equal(jwkA.crv == curve, true, "Export: Wrong curve name value");
                assert.equal(jwkA.x != null, true, "Export: X is missing");
                assert.equal(jwkA.y != null, true, "Export: Y is missing");
                assert.equal(jwkA.d != null, keyType == native.KeyType.PRIVATE, "Export: Key is missing");
                native.Key.importJwk(jwkA, keyType, function (err, key) {
                    assert(!err, true, "Import: " + err);
                    key.exportJwk(keyType, function (err, jwkB) {
                        assert(!err, true, "Export: " + err);
                        assert.equal(jwk_equal(jwkA, jwkB), true, "export values are different");
                        done();
                    });
                })
            })
        })
    }

    it("jwk EC private secp256k1", function (done) {
        test_ec_jwk("secp256k1", native.KeyType.PRIVATE, done);
    })

    it("jwk EC public secp256k1", function (done) {
        test_ec_jwk("secp256k1", native.KeyType.PUBLIC, done);
    })

    it("spki EC", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            test_export(key, true, done);
        })
    })

    it("pksc8 EC", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            test_export(key, false, done);
        })
    })

    it("AES generate 128", function (done) {
        native.AesKey.generate(16, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            done();
        });
    })

    it("AES generate 196", function (done) {
        native.AesKey.generate(24, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            done();
        });
    })

    it("AES generate 256", function (done) {
        native.AesKey.generate(32, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            done();
        });
    })

    it("AES CBC encrypt 256", function (done) {
        var msg = new Buffer("Hello world");
        native.AesKey.generate(32, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            key.encrypt("CBC", new Buffer("1234567890123456"), msg, function (err, data) {
                assert(!err, true, `encrypt: ${err}`);
                key.decrypt("CBC", new Buffer("1234567890123456"), data, function (err, m) {
                    assert(!err, true, `decrypt: ${err}`);
                    assert.equal(msg.toString(), m.toString());
                    done();
                });
            });
        });
    })

    it("AES CBC encrypt 256 error", function (done) {
        var msg = new Buffer("Hello world");
        native.AesKey.generate(32, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            key.encrypt("CBC", new Buffer("1234567890123456"), msg, function (err, data) {
                assert(!err, true, `encrypt: ${err}`);
                data[0] += 1;
                key.decrypt("CBC", new Buffer("1234567890123456"), data, function (err, m) {
                    assert(err, true, `must be error`);
                    done();
                });
            });
        });
    })

    it("AES export", function (done) {
        var raw;
        native.AesKey.generate(32, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            key.export(function (err, r) {
                assert(!err, true, `export: ${err}`);
                assert(r.length, 32, `export: wrong key length`);
                raw = r;
                native.AesKey.import(r, function (err, key) {
                    assert(!err, true, `import: ${err}`);
                    key.export(function (err, r) {
                        assert(!err, true, `export: ${err}`);
                        assert.equal(Buffer.compare(raw, r) == 0, true, "exported datas are not equal");
                        done();
                    });
                });
            });
        });
    })

    context("AES-KW", () => {

        it("WrapKey small data", done => {
            native.AesKey.generate(32, (err, key) => {
                assert(!err, true, `generate: ${err}`);
                key.wrapKey(new Buffer("123456789012345"), (err, data) => {
                    assert(!!err, true);
                    done();
                });
            });
        });

        it("UnwrapKey small data", done => {
            native.AesKey.generate(32, (err, key) => {
                assert(!err, true, `generate: ${err}`);
                key.unwrapKey(new Buffer("12345678901234567890123"), (err, data) => {
                    assert(!!err, true);
                    done();
                });
            });
        });

        it("WrapKey data is not % 8", done => {
            native.AesKey.generate(32, (err, key) => {
                assert(!err, true, `generate: ${err}`);
                key.wrapKey(new Buffer("12345678901234567"), (err, data) => {
                    assert(!!err, true);
                    done();
                });
            });
        });

        it("UnwrapKey data is not % 8", done => {
            native.AesKey.generate(32, (err, key) => {
                assert(!err, true, `generate: ${err}`);
                key.unwrapKey(new Buffer("1234567890123456789012346"), (err, data) => {
                    assert(!!err, true);
                    done();
                });
            });
        });

        [128, 192, 256].forEach(length => {
            it(`wrap/unwrap length:${length}`, done => {
                let MSG = new Buffer(length / 8);
                native.AesKey.generate(length / 8, (err, key) => {
                    assert(!err, true, `generate: ${err}`);
                    key.wrapKey(MSG, (err, data) => {
                        assert(!err, true, "Cannot wrap key");
                        key.unwrapKey(data, (err, data) => {
                            assert(!err, true, "Cannot unwrap key");
                            assert(data.toString("hex"), MSG.toString("hex"), "Cannot unwrap key");
                            done();
                        });
                    });
                });
            });
        });

    });

    function test_encrypt_gcm(keySize, aad, tag, done) {
        var msg = new Buffer("Hello world");
        native.AesKey.generate(keySize, function (err, key) {
            assert(!err, true, `generate: ${err}`);
            key.encryptGcm(new Buffer("1234567890123456"), msg, aad, tag, function (err, data) {
                assert(!err, true, `encrypt: ${err}`);
                key.decryptGcm(new Buffer("1234567890123456"), data, aad, tag, function (err, m) {
                    assert(!err, true, `decrypt: ${err}`);
                    assert.equal(Buffer.compare(msg, m) == 0, true, "Decrypt: Decrypted data is not equal");
                    done();
                });
            });
        });
    }

    it("AES GCM encrypt 192 AAD, tag(16)", function (done) {
        test_encrypt_gcm(24, new Buffer("1234567890123456"), 16, done);
    })

    it("AES GCM encrypt 192 no AAD, tag(4)", function (done) {
        test_encrypt_gcm(24, new Buffer(""), 4, done);
    })

    it("AES GCM encrypt 256 AAD, tag(16)", function (done) {
        test_encrypt_gcm(32, new Buffer("1234567890123456"), 16, done);
    })

    it("AES GCM encrypt 256 no AAD, tag(13)", function (done) {
        test_encrypt_gcm(32, new Buffer(""), 13, done);
    })

    function test_digest(md, mdlen, done) {
        native.Core.digest(md, TEST_MESSAGE, function (err, digest) {
            assert.equal(!err, true, err);
            assert.equal(digest.length, mdlen, "Wrong digest length");
            done()
        });
    }

    it("digest sha1", function (done) {
        test_digest("sha1", 20, done);
    })

    it("digest sha256", function (done) {
        test_digest("sha256", 32, done);
    })

    it("digest sha512", function (done) {
        test_digest("sha512", 64, done);
    })

    it("digest wrong name", function (done) {
        native.Core.digest("wrong name", TEST_MESSAGE, function (err, digest) {
            assert.equal(err != null, true, "Error is NULL");
            done()
        });
    })

    it("native RSA Key export/import jwk sync", function (done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            assert.equal(err == null, true, "error on key generation");
            // export key PRIVATE
            var jwk = key.exportJwk(native.KeyType.PRIVATE);
            assert.equal(!!jwk, true, "Can not export jwk");
            // import key PRIVATE
            var new_key = native.Key.importJwk(jwk, native.KeyType.PRIVATE);
            assert.equal(!!new_key, true, "Can not import jwk");

            // export key PUBLIC
            var jwk = key.exportJwk(native.KeyType.PUBLIC);
            assert.equal(!!jwk, true, "Can not export jwk");
            // import key PUBLIC
            var new_key = native.Key.importJwk(jwk, native.KeyType.PUBLIC);
            assert.equal(!!new_key, true, "Can not import jwk");
            done();
        })
    });

    it("native EC Key export/import jwk sync", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            assert.equal(err == null, true, "error on key generation");
            // export key PRIVATE
            var jwk = key.exportJwk(native.KeyType.PRIVATE);
            assert.equal(!!jwk, true, "Can not export jwk");
            // import key PRIVATE
            var new_key = native.Key.importJwk(jwk, native.KeyType.PRIVATE);
            assert.equal(!!new_key, true, "Can not import jwk");

            // export key PUBLIC
            var jwk = key.exportJwk(native.KeyType.PUBLIC);
            assert.equal(!!jwk, true, "Can not export jwk");
            // import key PUBLIC
            var new_key = native.Key.importJwk(jwk, native.KeyType.PUBLIC);
            assert.equal(!!new_key, true, "Can not import jwk");
            done();
        })
    });

    it("EC deriveBits P-256 256", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveBits(key, 256, function (err, bits) {
                if (!err)
                    assert.equal(bits.length, 256 / 8);
                done(err);
            });
        })
    });

    it("EC deriveBits P-256 128", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveBits(key, 128, function (err, bits) {
                if (!err)
                    assert.equal(bits.length, 128 / 8);
                done(err);
            });
        })
    });

    it("EC deriveBits P-256 512, error", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp256k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveBits(key, 512, function (err, bits) {
                assert.equal(!!err, true, "Should be error");
                done();
            });
        })
    });

    it("EC deriveBits P-521 528, error", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp521r1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveBits(key, 528, function (err, bits) {
                if (!err)
                    assert.equal(bits.length, 528 / 8);
                done(err);
            });
        })
    });

})