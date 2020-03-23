import * as crypto from "crypto";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { DesParams } from "webcrypto-core";
import { CryptoKey, CryptoKeyStorage } from "../../keys";
import { DesCryptoKey } from "./key";

export class DesCrypto {

  public static async generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<DesCryptoKey> {
    const key = DesCryptoKey.create({
      ...algorithm,
      name: algorithm.name.toUpperCase(),
    },
      "secret",
      extractable,
      keyUsages);
    key.native = crypto.randomBytes(algorithm.length >> 3);

    return key;
  }

  public static async exportKey(format: string, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const desKey = CryptoKeyStorage.getItem(key) as DesCryptoKey;
    switch (format.toLowerCase()) {
      case "jwk":
        return desKey.toJSON();
      case "raw":
        return new Uint8Array(desKey.native).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: KeyUsage[]) {
    let raw: ArrayBuffer;
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = keyData as JsonWebKey;
        raw = Convert.FromBase64Url(jwk.k!);
        break;
      case "raw":
        raw = keyData as ArrayBuffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    const desKey = DesCryptoKey.create(algorithm, "secret", extractable, keyUsages);
    desKey.algorithm.length = raw.byteLength >> 3;
    desKey.native = Buffer.from(raw);

    return desKey;
  }

  public static async encrypt(algorithm: DesParams, key: DesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
      case "DES-EDE3-CBC":
        return this.internalEncrypt(algorithm, key, Buffer.from(data), true);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async decrypt(algorithm: DesParams, key: DesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
      case "DES-EDE3-CBC":
        return this.internalEncrypt(algorithm, key, Buffer.from(data), false);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async internalEncrypt(algorithm: DesParams, key: DesCryptoKey, data: Buffer, encrypt: boolean) {
    const func = encrypt
      ? crypto.createCipheriv
      : crypto.createDecipheriv;
    const decipher = func.call(crypto, algorithm.name.toLowerCase(), key.native, core.BufferSourceConverter.toUint8Array(algorithm.iv));
    let resMessage = decipher.update(data);
    resMessage = Buffer.concat([resMessage, decipher.final()]);
    return new Uint8Array(resMessage).buffer;
  }

}
