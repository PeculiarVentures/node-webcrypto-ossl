import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import * as native from "../../native";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.internalEncrypt(algorithm, key, Buffer.from(data), true);
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.internalEncrypt(algorithm, key, Buffer.from(data), false);
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

  private internalEncrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer, encrypt: boolean): PromiseLike<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const rsaKey = CryptoKeyStorage.getItem(key) as RsaPrivateKey;
      const nativeKey = rsaKey.native as native.Key;
      const alg = this.getOsslAlgorithm(rsaKey.algorithm);

      let label: Buffer | null = null;
      if (algorithm.label) {
        label = Buffer.from(core.BufferSourceConverter.toArrayBuffer(algorithm.label));
      }

      nativeKey.RsaOaepEncDec(alg, data, label, !encrypt, (err, res) => {
        if (err) {
          reject(new core.CryptoError("NativeError: " + err));
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(res));
        }
      });
    });
  }

}
