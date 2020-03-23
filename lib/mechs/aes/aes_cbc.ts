import type { AesKey } from "native";
import * as core from "webcrypto-core";
import { CryptoKeyStorage } from "../../keys";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCbcProvider extends core.AesCbcProvider {

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

  public async onEncrypt(algorithm: AesCbcParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.internalEncrypt(algorithm, key, data, true);
  }

  public async onDecrypt(algorithm: AesCbcParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
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

  private async internalEncrypt(algorithm: AesCbcParams, key: AesCryptoKey, data: ArrayBuffer, encrypt: boolean): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const aesKey = CryptoKeyStorage.getItem(key).native as AesKey;
      const iv = Buffer.from(core.BufferSourceConverter.toArrayBuffer(algorithm.iv));

      const func: typeof aesKey.encrypt = encrypt
        ? aesKey.encrypt.bind(aesKey)
        : aesKey.decrypt.bind(aesKey);
      const buf = Buffer.from(data);
      func("CBC", iv, buf, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(core.BufferSourceConverter.toArrayBuffer(data2.buffer));
        }
      });
    });
  }
}
