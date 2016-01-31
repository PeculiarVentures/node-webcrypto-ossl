var assert = require('assert');
var native = require("../buildjs/native");
var base64url = require("base64url");

/**
 * Test with values from Chrome WebCrypto
 */

var RSA_KEY_JWK_JSON = '{"alg":"RS256","d":"Xm3Ko0c6w_cyFrIbkRQ-auHeOuZpdA5bvuRBCsG77A2ME2cvv_M6bVkrvNSvuDe4KcYwwXyWZrykfz9w0VZdvLKI_ijApfJLkgJLO63ij3Hu60c5jTfWWLQqmHzJAekC7gl7Bma-TU1LFz_1huXLnIBvYYr5U54g-KqKwB8tMbwDCvaLKfjREE8GcQMjMnajahlDvO5dntJH4LBPiJKteTMlDytPhIJYvVrwBqBeMjpNrxriR7uqq5anTs5KaQjkx4xojmJARuZUIGnD0xsxLyrimTGUdsfSCh99H1k05UtC1YpJETN_VRS6-byF5RA2RAs9trzE94nIqEHTrJgiAQ","dp":"3uqx9uTdbGnFfNYkHqiV5GPiPbrDsiEIZ5IUXLcHdxjqM0OxPMUJ4Ne_Q3gktFDhD3PsFW8uXTd8aU7pYEeKr_hXX6kGwCkKmhh9OXulkH-GzNgTtwWdl59dyS3jdgxjIy89YmvspzvQ9YGVUqFnvwTwY6GW1EqsV7F7ThDRngE","dq":"FqZZSuDyGFApAZL-7bEuqP5jm5RWx3X_mQPnMh6wNP6W-zK0SChQQgA6SkwD6YqJCfUheDUge0JzxiaLsfPH5qLnOhkNuCyFK7-nU-QZoY5YXMncRyQ_WVTD2EIGibfbNkXj3NAcLpcdn4KiTV8TGHQgvGFAii2UsGhmEYSj01k","e":"AQAB","ext":true,"key_ops":["sign"],"kty":"RSA","n":"wGOmA6DE8yF_Y-uMgBDufgxofCAXYr08HsiJc2VfVTDwCPB_hQSD9LpEwtvE_Ll_vMD3F4coYkN3Padb7zeRDTB4-WaA5qDB1r4CpFnqqn19888LzlGB1K2dyCR-VpaYx3FD8MQBuCnlgKxCXVDKWrYCWwQOyqJXbBBr8CFXLSYdi5Dm_2KeN3lXwLUFEXeYjfjAynKVoADvf4PouXzOxar40NPHAT7Jo32ZTv-TEfZGbW5XXsg-k0Dc98T31SRoUQEHqHY-4wEkh-HZBnWLm8gcjDLx92ZYekjO-HHiZvCX19FJZrrGu83_PipD7WQpVAd-fyoz4xlM30szPRTkdQ","p":"-wk92x0-1wQbsIS_CkdsZNTL5_x8tGl61pu0Q0QGm5U8JJb9sm42rZs_V1Ms-gZApeoOXTOE9HchT-qvkQKigwfuyplJbp-R714418MvXkhZuN-J0r_rS5hrlSPK4NZbLdjnoyK2VzTXPI7au7SYYXc1Vcms3liUYKBGYX-VyYE","q":"xDGIiMV_VQDsoxZqiaWabnmOyPtGcFxFiFcq53_GMrZwzPceEz0fAQgQDkn4voJsBRTBcw-nxRcLDQDxMmW0bOj8t83qyvQz-wUt7u1xInGd-5vh_OenrMSxMp0XeSUML2g32j0Ss3CuAPTCn1gw-ltldMzN1h2aBOi8u2fJDPU","qi":"ZtZnl4zsc4qUORq7QnOvBTGQFQTK-0OTZa9V4IfHNXXeTC76mtAhf5PmTAcFE-LPb_o3ivfwqbBITp8q2iGJYpiCMjgHUDg_UtOBp0J7EC5A5sBJT4GS0_4v9JbczmVS5qcDnOLf6-PbVCTogYaopguAGEasADPXAg1OgrDqNCs"}';

var EC_KEY_JWK_JSON = '{"crv":"P-256","d":"xJpMyGE7Q4Cic7UXcJCgisOH068dbD1DIvJxXbFOjnk","ext":true,"key_ops":["sign"],"kty":"EC","x":"vocRMfLYClci4XiGTZMVks1S6jyqu9muhlsr7WFPPRM","y":"C2x62g1tkwwGxJjddEdGd8v6TdP8_zGlaNhc6V7htIk"}';

var RSA_KEY_PKCS8 = new Buffer("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAY6YDoMTzIX9j64yAEO5+DGh8IBdivTweyIlzZV9VMPAI8H+FBIP0ukTC28T8uX+8wPcXhyhiQ3c9p1vvN5ENMHj5ZoDmoMHWvgKkWeqqfX3zzwvOUYHUrZ3IJH5WlpjHcUPwxAG4KeWArEJdUMpatgJbBA7KoldsEGvwIVctJh2LkOb/Yp43eVfAtQURd5iN+MDKcpWgAO9/g+i5fM7FqvjQ08cBPsmjfZlO/5MR9kZtbldeyD6TQNz3xPfVJGhRAQeodj7jASSH4dkGdYubyByMMvH3Zlh6SM74ceJm8JfX0Ulmusa7zf8+KkPtZClUB35/KjPjGUzfSzM9FOR1AgMBAAECggEAXm3Ko0c6w/cyFrIbkRQ+auHeOuZpdA5bvuRBCsG77A2ME2cvv/M6bVkrvNSvuDe4KcYwwXyWZrykfz9w0VZdvLKI/ijApfJLkgJLO63ij3Hu60c5jTfWWLQqmHzJAekC7gl7Bma+TU1LFz/1huXLnIBvYYr5U54g+KqKwB8tMbwDCvaLKfjREE8GcQMjMnajahlDvO5dntJH4LBPiJKteTMlDytPhIJYvVrwBqBeMjpNrxriR7uqq5anTs5KaQjkx4xojmJARuZUIGnD0xsxLyrimTGUdsfSCh99H1k05UtC1YpJETN/VRS6+byF5RA2RAs9trzE94nIqEHTrJgiAQKBgQD7CT3bHT7XBBuwhL8KR2xk1Mvn/Hy0aXrWm7RDRAablTwklv2ybjatmz9XUyz6BkCl6g5dM4T0dyFP6q+RAqKDB+7KmUlun5HvXjjXwy9eSFm434nSv+tLmGuVI8rg1lst2OejIrZXNNc8jtq7tJhhdzVVyazeWJRgoEZhf5XJgQKBgQDEMYiIxX9VAOyjFmqJpZpueY7I+0ZwXEWIVyrnf8YytnDM9x4TPR8BCBAOSfi+gmwFFMFzD6fFFwsNAPEyZbRs6Py3zerK9DP7BS3u7XEicZ37m+H856esxLEynRd5JQwvaDfaPRKzcK4A9MKfWDD6W2V0zM3WHZoE6Ly7Z8kM9QKBgQDe6rH25N1sacV81iQeqJXkY+I9usOyIQhnkhRctwd3GOozQ7E8xQng179DeCS0UOEPc+wVby5dN3xpTulgR4qv+FdfqQbAKQqaGH05e6WQf4bM2BO3BZ2Xn13JLeN2DGMjLz1ia+ynO9D1gZVSoWe/BPBjoZbUSqxXsXtOENGeAQKBgBamWUrg8hhQKQGS/u2xLqj+Y5uUVsd1/5kD5zIesDT+lvsytEgoUEIAOkpMA+mKiQn1IXg1IHtCc8Ymi7Hzx+ai5zoZDbgshSu/p1PkGaGOWFzJ3EckP1lUw9hCBom32zZF49zQHC6XHZ+Cok1fExh0ILxhQIotlLBoZhGEo9NZAoGAZtZnl4zsc4qUORq7QnOvBTGQFQTK+0OTZa9V4IfHNXXeTC76mtAhf5PmTAcFE+LPb/o3ivfwqbBITp8q2iGJYpiCMjgHUDg/UtOBp0J7EC5A5sBJT4GS0/4v9JbczmVS5qcDnOLf6+PbVCTogYaopguAGEasADPXAg1OgrDqNCs=", "base64");

var EC_KEY_PKCS8 = new Buffer("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxJpMyGE7Q4Cic7UXcJCgisOH068dbD1DIvJxXbFOjnmhRANCAAS+hxEx8tgKVyLheIZNkxWSzVLqPKq72a6GWyvtYU89EwtsetoNbZMMBsSY3XRHRnfL+k3T/P8xpWjYXOle4bSJ", "base64");

var RSA_OAEP_LABEL = new Buffer("1234567890123456");
var AES_IV = RSA_OAEP_LABEL;

var TEST_DATA = new Buffer("Hello world");

var RSA_SIGN = new Buffer("GXVeJK1fSJRO+jlO7UU+i+Joifa6lXY1loXAC39HfoFVMdgJs/7MerQ3/3L7SG1gDE2VN2pxVxu/RgLisCrOt4dxr1WK42Uoroqr5XJgGPsNEGcgzdeaI0dQn9amHIwfiJpw3uJbHMjabP4ttDujsvcubw/xz/KsskMPCxV2lhfyi3srVk/jMMdgkFIuReAZJSUHBYeQL0lgV6wur8Oz9C4YqcmpAkHkIrS6cPLyFt40t926ZaE3qXz7s/YpFtxEs77ED51BUH0aha4WlXmzGl2r/BzBfw9YtOF0i2We1KCsVIC0WVE6B8oRuZ8RB8bZZnLUwH6bJf9qzAhqw2e4CQ==", "base64");

var EC_SIGN = new Buffer("6CG1n5v+A3YfCdbNBaFdkuKob2hgHuAYGSuZlr0873SEFwhcTwBsj1RcweHWvybQ53OVlusmsxyzoP9EN/P3qA==", "base64");

var RSA_ENC = new Buffer("d9QbL9tbZ4ld0oAzC/upfsDClB/d2lfy/W8WwafJ6CIdclN5cZD5T4btpr19Kww36FQPL4hBanlkGwLQippPxd4eNk6a+uSJL5ibFEH0Jy7XGELuerSZNc09Wf3BmNTyh9e6vzpvFdElxOfWeKk2zzOgXpKbYjju96lbLigy1LYfaBaP9T3ZvrHuGUPyIzBWXNYXiHCvSOTWBsHaVZU5bGLsRXIH0Ai21zgKWv9aME7+IhpUICs5TeSAZ4M5v3FGrV9gtQqe5XJq0zgAAiKzl2uaTYBZtlGbIVD6gK5cg0HQ9z+GDxWWiGO4Q4y5l3P2P3HRQUVc9oj0hrjFWeDaOg==", "base64");

var RSA_ENC_LABEL = new Buffer("ADR0RhBr6aJ0K1dns5Hx5tHn8byEoqtlRVZ4VWpIgMp5e0E2S/8u1I4TDQ6+ZDshBWTzJfrA2oEvIBAgpaFKk68HDJJ3B6Nir/fn9naCRAwStqPfLeeDZJ+868vqtysbN8F9JeC3x1lw05Xoy4k8znIOTy9TbNmDHGK0LBa+D68Tre9Nvqhhz2th89FzRQ6Jf12jiiMYt9uKrEruW+xB59qi9YcT4rJOJND/WPdd4v27oYOGFRWOKYsdpbajhtHzjN2I76U327tmpGbulVJngy+V6X1XqLVMZbh0Jf9WX6CYH35Ryu1fP4xRzpYyXzxJEFhpJ9BEVrVilZIwnZyxjg==", "base64");

var EC_DERIVED_KEY = new Buffer("cmk/LtRfc8JTBTM25SH7KXKkpSRkzYCodFYLsXeukNM=", "base64");

var AES_KEY_RAW = new Buffer("StQFwEYbLh6cUxmmdwzjgLnlkBWIt6Rs+E19chbqasE=", "base64");

var AES_CBC_ENC = new Buffer("bcKv20ENhdt4G/IM79lGDA==", "base64");

function json_jwk(json) {
    var jwk = JSON.parse(json);
    var attrs = ["d", "dq", "n", "e", "p", "q", "qi", "dp", "dq"];
    for (var i in jwk) {
        if (attrs.indexOf(i) != -1) {
            jwk[i] = new Buffer(base64url.decode(jwk[i], "binary"), "binary");
        }
    }
    return jwk;
}

var RSA_KEY_JWK = json_jwk(RSA_KEY_JWK_JSON);
var EC_KEY_JWK = json_jwk(EC_KEY_JWK_JSON);

function test_sign(key, md, wc_sig, done) {
    // can not test sign for EC, only verify
    key.verify(md, TEST_DATA, wc_sig, function (err, v) {
        assert(!err, true, `"Verify: ${err}`);
        assert(v, true, `Verify: Signature is not valid for ${md}`);
        done();
    })
}


describe("native with webcrypto", function () {

    it("RSA sign sha256", function (done) {
        native.Key.importPkcs8(RSA_KEY_PKCS8, function (err, key) {
            assert.equal(err == null, true, "Import: can not import from PKCS8");
            test_sign(key, "sha256", RSA_SIGN, done);
        });
    })

    it("RSA encrypt sha256", function (done) {
        native.Key.importPkcs8(RSA_KEY_PKCS8, function (err, key) {
            assert.equal(err == null, true, "Import: can not import from PKCS8");
            key.RsaOaepEncDec("sha256", RSA_ENC, null, true, function (err, raw) {
                assert.equal(err == null, true, "Decrypt: can not decrypt");
                assert.equal(raw.toString() == TEST_DATA.toString(), true, "Wrong decrypted value");
                done();
            })
        });
    })

    it("RSA encrypt sha256 with label", function (done) {
        native.Key.importPkcs8(RSA_KEY_PKCS8, function (err, key) {
            assert.equal(err == null, true, "Import: can not import from PKCS8");
            key.RsaOaepEncDec("sha256", RSA_ENC_LABEL, RSA_OAEP_LABEL, true, function (err, raw) {
                assert.equal(err == null, true, "Decrypt: can not decrypt");
                assert.equal(raw.toString() == TEST_DATA.toString(), true, "Wrong decrypted value");
                done();
            })
        });
    })

    it("EC sign sha256", function (done) {
        native.Key.importPkcs8(EC_KEY_PKCS8, function (err, key) {
            assert.equal(err == null, true, "Import: can not import from PKCS8");
            test_sign(key, "sha256", EC_SIGN, done);
        });
    })

    it("EC deriveKey", function (done) {
        native.Key.importPkcs8(EC_KEY_PKCS8, function (err, key) {
            assert(!err, true, `"Import: ${err}`);
            key.EcdhDeriveKey(key, 32, function (err, data) {
                assert(!err, true, `"DeriveKey: ${err}`);
                assert.equal(Buffer.compare(data, EC_DERIVED_KEY) == 0, true, "DeriveKey: wrong key value");
                done();
            })
        });
    })

    it("AES CBC encrypt", function (done) {
        native.AesKey.import(AES_KEY_RAW, function (err, key) {
            assert(!err, true, `"Import: ${err}`);
            key.decrypt("CBC", AES_IV, AES_CBC_ENC, function (err, data) {
                assert(!err, true, `"Decrypt: ${err}`);
                assert.equal(Buffer.compare(TEST_DATA, data) == 0, true, "Decrypt: wrong decrypted value");
                done();
            })
        });
    })

})