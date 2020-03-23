import * as assert from "assert";
import * as os from "os";
import * as path from "path";
import * as rimraf from "rimraf";
import { Crypto } from "../lib";

const tmpDir = path.join(os.tmpdir(), "node-webcrypto-test");
const crypto = new Crypto({
  directory: tmpDir,
});

context("Crypto key storage", () => {

  after((done) => {
    rimraf(tmpDir, done);
  });

  context("Set/get item", () => {
    it("asymmetric", async () => {
      const alg: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;

      const index1 = await crypto.keyStorage.setItem(keys.privateKey);
      const index2 = await crypto.keyStorage.setItem(keys.publicKey);

      const indexes = await crypto.keyStorage.keys();
      assert.equal(indexes.includes(index1), true);
      assert.equal(indexes.includes(index2), true);
    });

    it("symmetric", async () => {
      const alg: AesKeyGenParams = { name: "AES-CBC", length: 128 };
      const key = await crypto.subtle.generateKey(alg, false, ["encrypt", "decrypt"]) as CryptoKey;

      const index = await crypto.keyStorage.setItem(key);

      const indexes = await crypto.keyStorage.keys();
      assert.equal(indexes.includes(index), true);

      crypto.keyStorage.hasItem(key);
    });
  });

  it("remove", async () => {
    const alg: AesKeyGenParams = { name: "AES-CBC", length: 128 };
    const key = await crypto.subtle.generateKey(alg, false, ["encrypt", "decrypt"]) as CryptoKey;

    const index = await crypto.keyStorage.setItem(key);
    await crypto.keyStorage.removeItem(index);

    const indexes = await crypto.keyStorage.keys();
    assert.equal(indexes.includes(index), false);
  });

  it("clear", async () => {
    const alg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    };
    const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;

    const index1 = await crypto.keyStorage.setItem(keys.privateKey);
    await crypto.keyStorage.setItem(keys.publicKey);

    const index = await crypto.keyStorage.indexOf(keys.privateKey);
    assert.equal(index, index1);

    await crypto.keyStorage.clear();

    const indexes = await crypto.keyStorage.keys();
    assert.equal(indexes.length, 0);
  });

});
