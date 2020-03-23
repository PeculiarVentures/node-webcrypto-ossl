import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import * as native from "../../native";
import { EcCrypto } from "./crypto";
import type { EcPrivateKey } from "./private_key";
import type { EcPublicKey } from "./public_key";

export class EcdsaProvider extends core.EcdsaProvider {

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return await EcCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);
  }

  public onSign(algorithm: EcdsaParams, key: EcPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const alg = this.getOsslAlgorithm(algorithm);
      const nativeKey = CryptoKeyStorage.getItem(key).native as native.Key;

      nativeKey.sign(alg, Buffer.from(data), (err, signature) => {
        if (err) {
          reject(new core.CryptoError(`NativeError: ${err.message}`));
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(signature));
        }
      });
    });
  }

  public async onVerify(algorithm: EcdsaParams, key: EcPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const alg = this.getOsslAlgorithm(algorithm);
      const nativeKey = CryptoKeyStorage.getItem(key).native as native.Key;

      nativeKey.verify(alg, Buffer.from(data), Buffer.from(signature), (err, res) => {
          if (err) {
              reject(new core.CryptoError(`NativeError: ${err.message}`));
          } else {
              resolve(res);
          }
      });
  });
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return EcCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(CryptoKeyStorage.getItem(key));
  }

  // @internal
  private getOsslAlgorithm(algorithm: EcdsaParams) {
    const alg = (algorithm.hash as Algorithm).name.toUpperCase().replace("-", "");
    return alg;
  }

}
