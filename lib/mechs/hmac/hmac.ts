import * as native from "native";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  public async onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      const length = (algorithm.length || this.getDefaultLength((algorithm.hash as Algorithm).name)) >> 3 << 3;
      native.HmacKey.generate(length, (err, key) => {
        if (err) {
          reject(err);
        } else {
          const hmacKey = HmacCryptoKey.create({...algorithm, length} as HmacKeyAlgorithm, "secret", extractable, keyUsages);
          hmacKey.native = key;
          resolve(CryptoKeyStorage.setItem(hmacKey));
        }
      });
    });
  }

  public async onSign(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const hmacKey = CryptoKeyStorage.getItem(key) as HmacCryptoKey;
      const alg = this.getOsslAlgorithm(hmacKey.algorithm);
      const nativeKey = hmacKey.native as native.Key;

      nativeKey.sign(alg, Buffer.from(data), (err, signature) => {
        if (err) {
          reject(new core.CryptoError(`NativeError: ${err.message}`));
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(signature));
        }
      });
    });
  }

  public async onVerify(algorithm: Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const signature2 = await this.sign(algorithm, key, data);
    return Buffer.from(signature2).compare(Buffer.from(signature)) === 0;
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      const formatLC = format.toLocaleLowerCase();
      let raw: ArrayBuffer;
      switch (formatLC) {
        case "jwk":
          const jwk = keyData as JsonWebKey;
          raw = Convert.FromBase64Url(jwk.k!);
          break;
        case "raw":
          raw = keyData as ArrayBuffer;
          break;
        default:
          throw new core.CryptoError(`ImportKey: Wrong format value '${format}'`);
      }
      native.HmacKey.import(Buffer.from(raw), (err, key) => {
        if (err) {
          reject(err);
        } else {
          const hmacKey = HmacCryptoKey.create(algorithm, "secret", extractable, keyUsages);
          hmacKey.native = key;
          resolve(CryptoKeyStorage.setItem(hmacKey));
        }
      });
    });
  }

  public async onExportKey(format: KeyFormat, key: HmacCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const nativeKey = CryptoKeyStorage.getItem(key).native as native.HmacKey;
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
          jwk.alg = "HS" + /-(\d+)$/.exec((key.algorithm as any).hash.name)![1];
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
        default: throw new core.CryptoError(`ExportKey: Unknown export format '${format}'`);
      }
    });
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(CryptoKeyStorage.getItem(key) instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

  private getOsslAlgorithm(algorithm: HmacKeyAlgorithm) {
    const alg = algorithm.hash.name.toUpperCase().replace("-", "");
    return alg;
  }

}
