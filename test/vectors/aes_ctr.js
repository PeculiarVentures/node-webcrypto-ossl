const assert = require('assert');
const crypto = require('../config');

let subtle = crypto.subtle;

const vectors = [
    {
        jwk: { "alg": "A128CTR", "ext": true, "k": "wblpP75XB3KdwybPxRGc2Q", "key_ops": ["encrypt", "decrypt"], "kty": "oct" },
        cases: [
            { "alg": { "name": "AES-CTR", "counter": [72, 6, 215, 190, 52, 28, 93, 142, 75, 91, 144, 228, 113, 9, 208, 133], "length": 1 }, "enc": [193, 189, 162, 32, 223, 172, 222, 52, 187, 167, 39, 181, 208, 44, 126, 93, 176, 4, 79, 4, 130, 166, 226, 189, 149, 29, 237, 84, 44, 220, 252, 10] },
            { "alg": { "name": "AES-CTR", "counter": [104, 47, 145, 47, 244, 208, 205, 182, 73, 234, 98, 184, 169, 170, 111, 165], "length": 64 }, "enc": [110, 228, 115, 255, 104, 191, 247, 184, 208, 161, 78, 2, 51, 217, 163, 78, 206, 163, 189, 182, 175, 118, 209, 195, 193, 242, 102, 82, 75, 5, 234, 102] },
            { "alg": { "name": "AES-CTR", "counter": [210, 96, 48, 120, 7, 80, 60, 108, 216, 204, 177, 31, 55, 33, 117, 203], "length": 128 }, "enc": [241, 215, 176, 82, 243, 175, 69, 36, 77, 40, 161, 159, 68, 203, 131, 141, 149, 166, 197, 190, 152, 241, 169, 193, 56, 31, 39, 76, 140, 234, 222, 101] },
        ],
    },
    {
        jwk: { "alg": "A256CTR", "ext": true, "k": "cHH9uWDZf4cVmB4witwb2SAuz5YxkjfCvwOA_7ABg1Q", "key_ops": ["encrypt", "decrypt"], "kty": "oct" },
        cases: [
            { "alg": { "name": "AES-CTR", "counter": [134, 8, 205, 173, 139, 24, 215, 128, 242, 111, 73, 240, 184, 89, 70, 218], "length": 1 }, "enc": [168, 195, 174, 76, 227, 188, 11, 95, 94, 72, 155, 252, 50, 64, 164, 87, 149, 244, 159, 147, 59, 96, 215, 165, 141, 30, 23, 4, 213, 197, 190, 120] },
            { "alg": { "name": "AES-CTR", "counter": [42, 70, 216, 161, 245, 141, 42, 24, 185, 40, 27, 88, 195, 14, 43, 81], "length": 64 }, "enc": [18, 38, 41, 103, 213, 43, 195, 238, 29, 58, 109, 12, 102, 45, 65, 221, 215, 169, 237, 87, 25, 117, 205, 7, 37, 116, 2, 80, 78, 223, 235, 254] },
            { "alg": { "name": "AES-CTR", "counter": [117, 196, 244, 158, 61, 217, 68, 197, 73, 221, 65, 221, 0, 103, 191, 156], "length": 128 }, "enc": [108, 251, 65, 164, 220, 203, 47, 24, 177, 179, 214, 59, 87, 131, 144, 119, 42, 118, 246, 141, 124, 161, 213, 237, 231, 22, 191, 99, 31, 54, 21, 46] }
        ]
    }
];

// Data for encryption is empty array of 16 bytes
const data = new Uint8Array(32);

context("Vectors", () => {

    context("AES-CTR", () => {

        vectors.forEach((vector) => {
            context(vector.jwk.alg, () => {
                vector.cases.forEach((item) => {
                    it(`length: ${item.alg.length}`, (done) => {
                        crypto.subtle.importKey("jwk", vector.jwk, { name: "AES-CTR" }, true, ["encrypt", "decrypt"])
                            .then((key) => {
                                const alg = { name: "AES-CTR", counter: new Uint8Array(item.alg.counter), length: item.alg.length };
                                return crypto.subtle.encrypt(alg, key, data)
                                    .then((enc) => {
                                        assert.equal(Buffer.compare(
                                            new Buffer(item.enc),
                                            new Buffer(enc)
                                        ), 0)
                                        return crypto.subtle.decrypt(alg, key, enc)
                                    })
                                    .then((dec) => {
                                        assert.equal(Buffer.compare(
                                            new Buffer(data),
                                            new Buffer(dec)
                                        ), 0)
                                    })
                                    .then(done, done);
                            })
                    });
                })
            })
        })

    });

});
