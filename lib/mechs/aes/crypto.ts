import * as native from "native";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import { AesCryptoKey } from "./key";

export class AesCrypto {

  public static generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<AesCryptoKey> {
    return new Promise<AesCryptoKey>((resolve, reject) => {
      native.AesKey.generate(algorithm.length / 8, (err, key) => {
        if (err) {
          reject(err);
        } else {
          const secret = AesCryptoKey.create(algorithm, "secret", extractable, keyUsages);
          secret.native = key;
          resolve(secret);
        }
      });
    });
  }

  public static exportKey(format: string, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return new Promise<JsonWebKey | ArrayBuffer>((resolve, reject) => {
      const nativeKey = key.native as native.AesKey;
      switch (format.toLocaleLowerCase()) {
        case "jwk":
          const jwk: JsonWebKey = {
            kty: "oct",
            alg: "",
            key_ops: key.usages,
            k: "",
            ext: true,
          };
          // set alg
          jwk.alg = `A${key.algorithm.length}${/-(\w+)$/.exec(key.algorithm.name)![1].toUpperCase()}`;
          nativeKey.export((err, data) => {
            if (err) {
              reject(err);
            } else {
              jwk.k = Convert.ToBase64Url(data);
              resolve(jwk);
            }
          });
          break;
        case "raw":
          nativeKey.export((err, data) => {
            if (err) {
              reject(err);
            } else {
              resolve(core.BufferSourceConverter.toArrayBuffer(data));
            }
          });
          break;
        default:
          throw new core.OperationError("format: Must be 'jwk' or 'raw'");
      }
    });
  }

  public static async importKey(format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: KeyUsage[]): Promise<AesCryptoKey> {
    return new Promise<AesCryptoKey>((resolve, reject) => {
      const formatLC = format.toLocaleLowerCase();
      let raw: ArrayBuffer;
      switch (formatLC) {
        case "jwk":
          raw = Convert.FromBase64Url((keyData as JsonWebKey).k!);
          break;
        case "raw":
          raw = keyData as ArrayBuffer;
          break;
        default:
          throw new core.OperationError("format: Must be 'jwk' or 'raw'");
      }

      // check key length
      const keyLengthBits = raw.byteLength << 3;
      switch (keyLengthBits) {
        case 128:
        case 192:
        case 256:
          break;
        default:
          throw new core.OperationError("keyData: Is wrong key length");
      }

      native.AesKey.import(Buffer.from(raw), (err, key) => {
        if (err) {
          reject(err);
        } else {
          const secret = AesCryptoKey.create({ ...algorithm, length: keyLengthBits }, "secret", extractable, keyUsages);
          secret.native = key;
          resolve(secret);
        }
      });
    });
  }

  public static checkCryptoKey(key: core.NativeCryptoKey): asserts key is AesCryptoKey {
    if (!(CryptoKeyStorage.getItem(key) instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not a AesCryptoKey");
    }
  }
}
