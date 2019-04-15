"use strict";
const assert = require('assert');
const webcrypto = require('../config');
const subtle = webcrypto.subtle;

// Chrome vectors
const vectors = [
    {
        alg: { name: "HMAC", hash: "SHA-1", length: 128 },
        jwk: { alg: "HS1", ext: true, k: "-Dq509EtZLK74okYtquhbA", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "c56c7d4180cc686b4ae4ad1c802b172f5be506cb"
    },
    {
        alg: { name: "HMAC", hash: "SHA-1", length: 256 },
        jwk: { alg: "HS1", ext: true, k: "dnUKLkxLZxej051UJuzsZc1slDGGjXGGpkN1Cb3v-v0", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "a7cbad583bf770ad72b6946034f7dd46a7c9fa39"
    },
    {
        alg: { name: "HMAC", hash: "SHA-1", length: 512 },
        jwk: { alg: "HS1", ext: true, k: "qpMW7xZOo9nsyNudtzEm6TjwSSWUJNrtPc50J25mhsbMHTx10za768wmUE__VjAF1ngU08EdrAHUzAiwbpIXSQ", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "a7c1bb7bb4165bf1c793d9ec19bc08d15e7608ff"
    },
    {
        alg: { name: "HMAC", hash: "SHA-256", length: 128 },
        jwk: { alg: "HS256", ext: true, k: "QOqmJzfzNTH9iIIT6ipz_Q", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "f2607dd928f7e40d896948e44c2facbf3a6e1870394d44f24c990e12ce4bd6fd"
    },
    {
        alg: { name: "HMAC", hash: "SHA-256", length: 256 },
        jwk: { alg: "HS256", ext: true, k: "om_Vtxu9zWdRWMmfsBxO3P7J3miVQfqMumYMC2Qs4Yk", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "1c9f203b417791c39faf7e2c6b4d471bdb9ee4f83d61ef806435b324d8083f31"
    },
    {
        alg: { name: "HMAC", hash: "SHA-256", length: 512 },
        jwk: { alg: "HS256", ext: true, k: "Jf__Ri3OoD4b-oTa6HCE7n_3Bv946gPGQBOalZlbKib8JmY4h6zi5s9fLRqL0t-3eDHdWQFTXG4mgytsdde0Jg", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "ff5df6b852cee090b7b4b749a27f96f44c4d0f040737b6acb37ff5f7831a682a"
    },
    {
        alg: { name: "HMAC", hash: "SHA-384", length: 128 },
        jwk: { alg: "HS384", ext: true, k: "U2RQ9yrjnY1wQVWx216QzQ", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "d9e5c53a1eecc191c4d938ed271e443600b66d8f9e33f4d10f16c43d87c1c483d4f3ff8c8d179a607542c74ddd57534a"
    },
    {
        alg: { name: "HMAC", hash: "SHA-384", length: 256 },
        jwk: { alg: "HS384", ext: true, k: "TT1ZRmZQfPK0bmyVrlOWUrSV--Ser8dzLYn1vu55qSc", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "f8d367f33da05b9502f5d2cceff51b4255d396993c2613d3007eb6712fdff67ca906f450bc2bcb7354e512dc8620c63d"
    },
    {
        alg: { name: "HMAC", hash: "SHA-384", length: 512 },
        jwk: { alg: "HS384", ext: true, k: "vF09sr6-5FTeUZHrhhC5V0X8WdAYoh7KwTxnTV0KnewEf628v8oQ49bshNMW77gHkZ945mM4Md9m7Fits7KNlw", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "266816cf3991a64b42e3404e66ee0bf9cbff71acb7bd6191fb0767259d4c2a720e821d7b207efadbcf75f30de5244e09"
    },
    {
        alg: { name: "HMAC", hash: "SHA-512", length: 128 },
        jwk: { alg: "HS512", ext: true, k: "Yn_jCCwZ4INOs134rrDVWg", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "90e83fe5a36476b7b8b1d146902aa2b8f86b434cc52fb613ea707055af5ab6746409cb8879013df6d419124c277822162c789ba0f8f0d62bc21c695ccf80b7f8"
    },
    {
        alg: { name: "HMAC", hash: "SHA-512", length: 256 },
        jwk: { alg: "HS512", ext: true, k: "Y_dUCka9YT5G2bnyST_7UoopFHmAhAWRXdLUo0b4PZw", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "af50024232800369d95afa6800ca913c784e98da06dee591cc5e119a08b1f38ad5a41e41c5789fa4f414b54a92104b522c15ef8d09ee49fc1f016170d7daef4e"
    },
    {
        alg: { name: "HMAC", hash: "SHA-512", length: 512 },
        jwk: { alg: "HS512", ext: true, k: "YMhyJ0EPxePMgJJ7_gtzPMvX-_7lhesoF9kg9pLSPFqcMYqk13uwtM_EWi-jm_tE3va4rK9Qd8oTHp8UH2xnpw", key_ops: ["sign", "verify"], kty: "oct" },
        signature: "2bcdf62e54131a83a8fb27c3405ee79463802491b10c1d6421f3aba3255f28685f74e717ea8ee13cb5c688898856dce92cd91512d1276167b5db6b16baf6d187"
    }
]

describe("WebCrypto", () => {
    context("HMAC", () => {
        vectors.forEach(vector =>
            it(`hash:${vector.alg.hash} length:${vector.alg.length}`, done => {
                subtle.importKey("jwk", vector.jwk, vector.alg, true, ["sign", "verify"])
                    .then(key => {
                        return subtle.verify(vector.alg, key, Buffer.from(vector.signature, "hex"), Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
                    })
                    .then(res => {
                        assert.equal(res, true);
                        done();
                    })
                    .catch(done);
            })
        );
    });
});