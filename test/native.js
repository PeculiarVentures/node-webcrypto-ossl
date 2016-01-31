var assert = require('assert');
var native = require("../buildjs/native");
var base64url = require("base64url");

var RSA_KEY_JWK_JSON = '{"alg":"RS256","d":"Xm3Ko0c6w_cyFrIbkRQ-auHeOuZpdA5bvuRBCsG77A2ME2cvv_M6bVkrvNSvuDe4KcYwwXyWZrykfz9w0VZdvLKI_ijApfJLkgJLO63ij3Hu60c5jTfWWLQqmHzJAekC7gl7Bma-TU1LFz_1huXLnIBvYYr5U54g-KqKwB8tMbwDCvaLKfjREE8GcQMjMnajahlDvO5dntJH4LBPiJKteTMlDytPhIJYvVrwBqBeMjpNrxriR7uqq5anTs5KaQjkx4xojmJARuZUIGnD0xsxLyrimTGUdsfSCh99H1k05UtC1YpJETN_VRS6-byF5RA2RAs9trzE94nIqEHTrJgiAQ","dp":"3uqx9uTdbGnFfNYkHqiV5GPiPbrDsiEIZ5IUXLcHdxjqM0OxPMUJ4Ne_Q3gktFDhD3PsFW8uXTd8aU7pYEeKr_hXX6kGwCkKmhh9OXulkH-GzNgTtwWdl59dyS3jdgxjIy89YmvspzvQ9YGVUqFnvwTwY6GW1EqsV7F7ThDRngE","dq":"FqZZSuDyGFApAZL-7bEuqP5jm5RWx3X_mQPnMh6wNP6W-zK0SChQQgA6SkwD6YqJCfUheDUge0JzxiaLsfPH5qLnOhkNuCyFK7-nU-QZoY5YXMncRyQ_WVTD2EIGibfbNkXj3NAcLpcdn4KiTV8TGHQgvGFAii2UsGhmEYSj01k","e":"AQAB","ext":true,"key_ops":["sign"],"kty":"RSA","n":"wGOmA6DE8yF_Y-uMgBDufgxofCAXYr08HsiJc2VfVTDwCPB_hQSD9LpEwtvE_Ll_vMD3F4coYkN3Padb7zeRDTB4-WaA5qDB1r4CpFnqqn19888LzlGB1K2dyCR-VpaYx3FD8MQBuCnlgKxCXVDKWrYCWwQOyqJXbBBr8CFXLSYdi5Dm_2KeN3lXwLUFEXeYjfjAynKVoADvf4PouXzOxar40NPHAT7Jo32ZTv-TEfZGbW5XXsg-k0Dc98T31SRoUQEHqHY-4wEkh-HZBnWLm8gcjDLx92ZYekjO-HHiZvCX19FJZrrGu83_PipD7WQpVAd-fyoz4xlM30szPRTkdQ","p":"-wk92x0-1wQbsIS_CkdsZNTL5_x8tGl61pu0Q0QGm5U8JJb9sm42rZs_V1Ms-gZApeoOXTOE9HchT-qvkQKigwfuyplJbp-R714418MvXkhZuN-J0r_rS5hrlSPK4NZbLdjnoyK2VzTXPI7au7SYYXc1Vcms3liUYKBGYX-VyYE","q":"xDGIiMV_VQDsoxZqiaWabnmOyPtGcFxFiFcq53_GMrZwzPceEz0fAQgQDkn4voJsBRTBcw-nxRcLDQDxMmW0bOj8t83qyvQz-wUt7u1xInGd-5vh_OenrMSxMp0XeSUML2g32j0Ss3CuAPTCn1gw-ltldMzN1h2aBOi8u2fJDPU","qi":"ZtZnl4zsc4qUORq7QnOvBTGQFQTK-0OTZa9V4IfHNXXeTC76mtAhf5PmTAcFE-LPb_o3ivfwqbBITp8q2iGJYpiCMjgHUDg_UtOBp0J7EC5A5sBJT4GS0_4v9JbczmVS5qcDnOLf6-PbVCTogYaopguAGEasADPXAg1OgrDqNCs"}';

var RSA_KEY_PKCS8 = new Buffer("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAY6YDoMTzIX9j64yAEO5+DGh8IBdivTweyIlzZV9VMPAI8H+FBIP0ukTC28T8uX+8wPcXhyhiQ3c9p1vvN5ENMHj5ZoDmoMHWvgKkWeqqfX3zzwvOUYHUrZ3IJH5WlpjHcUPwxAG4KeWArEJdUMpatgJbBA7KoldsEGvwIVctJh2LkOb/Yp43eVfAtQURd5iN+MDKcpWgAO9/g+i5fM7FqvjQ08cBPsmjfZlO/5MR9kZtbldeyD6TQNz3xPfVJGhRAQeodj7jASSH4dkGdYubyByMMvH3Zlh6SM74ceJm8JfX0Ulmusa7zf8+KkPtZClUB35/KjPjGUzfSzM9FOR1AgMBAAECggEAXm3Ko0c6w/cyFrIbkRQ+auHeOuZpdA5bvuRBCsG77A2ME2cvv/M6bVkrvNSvuDe4KcYwwXyWZrykfz9w0VZdvLKI/ijApfJLkgJLO63ij3Hu60c5jTfWWLQqmHzJAekC7gl7Bma+TU1LFz/1huXLnIBvYYr5U54g+KqKwB8tMbwDCvaLKfjREE8GcQMjMnajahlDvO5dntJH4LBPiJKteTMlDytPhIJYvVrwBqBeMjpNrxriR7uqq5anTs5KaQjkx4xojmJARuZUIGnD0xsxLyrimTGUdsfSCh99H1k05UtC1YpJETN/VRS6+byF5RA2RAs9trzE94nIqEHTrJgiAQKBgQD7CT3bHT7XBBuwhL8KR2xk1Mvn/Hy0aXrWm7RDRAablTwklv2ybjatmz9XUyz6BkCl6g5dM4T0dyFP6q+RAqKDB+7KmUlun5HvXjjXwy9eSFm434nSv+tLmGuVI8rg1lst2OejIrZXNNc8jtq7tJhhdzVVyazeWJRgoEZhf5XJgQKBgQDEMYiIxX9VAOyjFmqJpZpueY7I+0ZwXEWIVyrnf8YytnDM9x4TPR8BCBAOSfi+gmwFFMFzD6fFFwsNAPEyZbRs6Py3zerK9DP7BS3u7XEicZ37m+H856esxLEynRd5JQwvaDfaPRKzcK4A9MKfWDD6W2V0zM3WHZoE6Ly7Z8kM9QKBgQDe6rH25N1sacV81iQeqJXkY+I9usOyIQhnkhRctwd3GOozQ7E8xQng179DeCS0UOEPc+wVby5dN3xpTulgR4qv+FdfqQbAKQqaGH05e6WQf4bM2BO3BZ2Xn13JLeN2DGMjLz1ia+ynO9D1gZVSoWe/BPBjoZbUSqxXsXtOENGeAQKBgBamWUrg8hhQKQGS/u2xLqj+Y5uUVsd1/5kD5zIesDT+lvsytEgoUEIAOkpMA+mKiQn1IXg1IHtCc8Ymi7Hzx+ai5zoZDbgshSu/p1PkGaGOWFzJ3EckP1lUw9hCBom32zZF49zQHC6XHZ+Cok1fExh0ILxhQIotlLBoZhGEo9NZAoGAZtZnl4zsc4qUORq7QnOvBTGQFQTK+0OTZa9V4IfHNXXeTC76mtAhf5PmTAcFE+LPb/o3ivfwqbBITp8q2iGJYpiCMjgHUDg/UtOBp0J7EC5A5sBJT4GS0/4v9JbczmVS5qcDnOLf6+PbVCTogYaopguAGEasADPXAg1OgrDqNCs=", "base64");

var RSA_SIGN = new Buffer("GXVeJK1fSJRO+jlO7UU+i+Joifa6lXY1loXAC39HfoFVMdgJs/7MerQ3/3L7SG1gDE2VN2pxVxu/RgLisCrOt4dxr1WK42Uoroqr5XJgGPsNEGcgzdeaI0dQn9amHIwfiJpw3uJbHMjabP4ttDujsvcubw/xz/KsskMPCxV2lhfyi3srVk/jMMdgkFIuReAZJSUHBYeQL0lgV6wur8Oz9C4YqcmpAkHkIrS6cPLyFt40t926ZaE3qXz7s/YpFtxEs77ED51BUH0aha4WlXmzGl2r/BzBfw9YtOF0i2We1KCsVIC0WVE6B8oRuZ8RB8bZZnLUwH6bJf9qzAhqw2e4CQ==", "base64");

function json_jwk(json) {
    var jwk = JSON.parse(json);
    var attrs = ["d", "dq", "n", "e", "p", "q", "qi", "dp", "dq"];
    for (var i in jwk) {
        if (attrs.indexOf(i) != -1){
            jwk[i] = new Buffer(base64url.decode(jwk[i], "binary"), "binary");
        }
    }
    return jwk;
}

var RSA_KEY_JWK = json_jwk(RSA_KEY_JWK_JSON);

// console.log(native);

describe("native", function () {

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
    })

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

    function test_sign(key, md, done, wc_sig) {
        var message = new Buffer("Hello world");

        key.sign(md, message, function (err, sig) {
            assert(sig != null, true, "Error on sign");
            key.verify(md, message, sig, function (err, v) {
                assert(v, true, "Signature is not valid");
                if (wc_sig) {
                    assert.equal(Buffer.compare(wc_sig, sig) == 0, true, "Signature is different from webcrypto");
                }
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

    it("webcrypto RSA sign sha256", function (done) {
        native.Key.importPkcs8(RSA_KEY_PKCS8, function (err, key) {
            assert.equal(err == null, true, "error on sign");
            test_sign(key, "sha256", done, RSA_SIGN);
        });
    })

    function test_rsa_oaep_enc_dec(md, message, label, done) {
        native.Key.generateRsa(1024, native.RsaPublicExponent.RSA_3, function (err, key) {
            key.RsaOaepEncDec(md, message, label, false, function (err, dec) {
                assert(dec != null, true, "Error on encrypt");
                key.RsaOaepEncDec(md, dec, label, true, function (err, msg) {
                    assert(msg != null, true, "Error on decrypt");
                    assert(Buffer.compare(msg, message) === 0, true, "Wron resul value");
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

    it("generate EC secp192k1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            done();
        })
    })

    it("sign EC secp192k1 sha1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            test_sign(key, "sha1", done);
        })
    })

    it("deriveKey EC secp192k1", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            assert(key != null, true, "Error on key generation");
            key.EcdhDeriveKey(key, 128, function (err, b) {
                assert(b != null, true, "Error on key derive");
                done();
            })
        })
    })

    function jwk_equal(a, b) {
        var json1 = JSON.stringify(a);
        var json2 = JSON.stringify(b);
        return json1 == json2;
    }

    function test_ec_jwk(curveName, keyType, done) {

        var curve = native.EcNamedCurves[curveName]
        assert.equal(curve != null, true, "Unknown curve name");

        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
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

    it("jwk EC private secp192k1", function (done) {
        test_ec_jwk("secp192k1", native.KeyType.PRIVATE, done);
    })

    it("jwk EC public secp192k1", function (done) {
        test_ec_jwk("secp192k1", native.KeyType.PUBLIC, done);
    })

    it("spki EC", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
            test_export(key, true, done);
        })
    })

    it("pksc8 EC", function (done) {
        native.Key.generateEc(native.EcNamedCurves.secp192k1, function (err, key) {
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



})