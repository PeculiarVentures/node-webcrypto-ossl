import * as core from "webcrypto-core";
import { CryptoKey, CryptoKeyStorage } from "../../keys";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesCbcParams = core.DesParams;

export class DesCbcProvider extends core.DesProvider {

  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-CBC";

  public async onGenerateKey(algorithm: core.DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await DesCrypto.generateKey(
      {
        name: this.name,
        length: this.keySizeBits,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: DesCbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const desKey = CryptoKeyStorage.getItem(key) as DesCryptoKey;
    return DesCrypto.encrypt(algorithm, desKey, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: DesCbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const desKey = CryptoKeyStorage.getItem(key) as DesCryptoKey;
    return DesCrypto.decrypt(algorithm, desKey, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return DesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await DesCrypto.importKey(format, keyData, { name: this.name, length: this.keySizeBits }, extractable, keyUsages);
    if (key.native.length !== (this.keySizeBits >> 3)) {
      throw new core.OperationError("keyData: Wrong key size");
    }
    return CryptoKeyStorage.setItem(key);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(CryptoKeyStorage.getItem(key) instanceof DesCryptoKey)) {
      throw new TypeError("key: Is not a DES CryptoKey");
    }
  }

}
