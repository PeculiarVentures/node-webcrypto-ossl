import * as native from "native";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { CryptoKeyStorage } from "../../keys";
import { EcCrypto } from "./crypto";

export class EcdhProvider extends core.EcdhProvider {

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

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    return EcCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const nativeKey = CryptoKeyStorage.getItem(baseKey).native as native.Key;
      const publicKey = CryptoKeyStorage.getItem(algorithm.public).native as native.Key;
      // derive bits
      nativeKey.EcdhDeriveBits(publicKey, length, (err, raw) => {
          if (err) {
              reject(err);
          } else {
              resolve(core.BufferSourceConverter.toArrayBuffer(raw));
          }
      });
  });
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(CryptoKeyStorage.getItem(key));
  }

}
