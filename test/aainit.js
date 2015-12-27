var assert = require('assert');
var WebCrypto = require("../buildjs/webcrypto.js").default;

describe("Init", function () {
    var webcrypto;
    var keys = [];

    it("Init", function () {
        webcrypto = new WebCrypto();

        global.webcrypto = webcrypto;
        global.keys = keys;
        assert.notEqual(global.webcrypto == null, true, "WebCrypto is not initialized");
    })
})