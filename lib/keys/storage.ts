import * as core from "webcrypto-core";
import { CryptoKey as InternalCryptoKey } from "./key";

const keyStorage = new WeakMap<core.CryptoKey, InternalCryptoKey>();

export class CryptoKeyStorage {
  public static getItem(key: core.CryptoKey) {
    const res = keyStorage.get(key);
    if (!res) {
      throw new core.OperationError("Cannot get CryptoKey from secure storage");
    }
    return res;
  }

  public static setItem(value: InternalCryptoKey) {
    const key = core.CryptoKey.create(value.algorithm, value.type, value.extractable, value.usages);
    Object.freeze(key);

    keyStorage.set(key, value);

    return key;
  }
}
