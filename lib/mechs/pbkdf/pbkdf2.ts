import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import * as native from "../../native";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {

  public getOsslAlgorithm(algorithm: Algorithm) {
    const alg = algorithm.name.toUpperCase().replace("-", "");
    return alg;
  }

  public async onDeriveBits(algorithm: Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const nativeKey = CryptoKeyStorage.getItem(baseKey).native as native.Pbkdf2Key;
      const hash = algorithm.hash as Algorithm;
      const salt = Buffer.from(core.BufferSourceConverter.toArrayBuffer(algorithm.salt));
      // derive bits
      nativeKey.deriveBits(this.getOsslAlgorithm(hash), salt, algorithm.iterations, length, (err, raw) => {
        if (err) {
          reject(err);
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(raw));
        }
      });
    });
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      let raw: ArrayBuffer;
      switch (format) {
        case "raw":
          raw = keyData as ArrayBuffer;
          break;
        default:
          throw new core.OperationError("format: Must be 'raw'");
      }
      native.Pbkdf2Key.importKey(Buffer.from(raw), (err, key) => {
        if (err) {
          reject(err);
        } else {
          const pbkdf2Key = PbkdfCryptoKey.create(algorithm, "secret", false, keyUsages);
          pbkdf2Key.native = key;
          resolve(CryptoKeyStorage.setItem(pbkdf2Key));

        }
      });
    });
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(CryptoKeyStorage.getItem(key) instanceof PbkdfCryptoKey)) {
      throw new TypeError("key: Is not PBKDF CryptoKey");
    }
  }

}
