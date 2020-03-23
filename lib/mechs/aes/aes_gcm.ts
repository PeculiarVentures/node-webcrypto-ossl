import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import type { AesKey } from "../../native";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesGcmProvider extends core.AesGcmProvider {

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return CryptoKeyStorage.setItem(key);
  }

  public async onEncrypt(algorithm: AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.internalEncrypt(algorithm, key, data, true);
  }

  public async onDecrypt(algorithm: AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.internalEncrypt(algorithm, key, data, false);
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, CryptoKeyStorage.getItem(key) as AesCryptoKey);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const res = await AesCrypto.importKey(format, keyData, { name: this.name }, extractable, keyUsages);
    return CryptoKeyStorage.setItem(res);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }

  private async internalEncrypt(algorithm: AesGcmParams, key: AesCryptoKey, data: ArrayBuffer, encrypt: boolean): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const aesKey = CryptoKeyStorage.getItem(key).native as AesKey;
      const iv = Buffer.from(core.BufferSourceConverter.toArrayBuffer(algorithm.iv));
      const aad = algorithm.additionalData ? Buffer.from(algorithm.additionalData as Uint8Array) : Buffer.alloc(0);
      const tagLength = algorithm.tagLength || 128;

      const func: typeof aesKey.encryptGcm = encrypt
        ? aesKey.encryptGcm.bind(aesKey)
        : aesKey.decryptGcm.bind(aesKey);
      func(iv, Buffer.from(data), aad || Buffer.alloc(0), tagLength >> 3, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(data2.buffer));
        }
      });
    });
  }
}
