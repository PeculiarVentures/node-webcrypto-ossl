import * as native from "native";
import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";

export class RsaPssProvider extends core.RsaPssProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);
  }

  public onSign(algorithm: RsaPssParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const rsaKey = CryptoKeyStorage.getItem(key) as RsaPrivateKey;
      const alg = this.getOsslAlgorithm(rsaKey.algorithm);
      const nativeKey = rsaKey.native as native.Key;

      nativeKey.RsaPssSign(alg, algorithm.saltLength, Buffer.from(data), (err, signature) => {
        if (err) {
          reject(new core.CryptoError("NativeError: " + err.message));
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(signature));
        }
      });
    });
  }
  public onVerify(algorithm: RsaPssParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const rsaKey = CryptoKeyStorage.getItem(key) as RsaPrivateKey;
      const alg = this.getOsslAlgorithm(rsaKey.algorithm);
      const nativeKey = rsaKey.native as native.Key;

      nativeKey.RsaPssVerify(alg, algorithm.saltLength, Buffer.from(data), Buffer.from(signature), (err, res) => {
        if (err) {
          reject(new core.CryptoError("NativeError: " + err.message));
        } else {
          resolve(res);
        }
      });
    });
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(CryptoKeyStorage.getItem(key));
  }

  private getOsslAlgorithm(algorithm: RsaHashedKeyAlgorithm) {
    const alg = algorithm.hash.name.toUpperCase().replace("-", "");
    return alg;
  }

}
