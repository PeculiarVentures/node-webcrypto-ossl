import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public native: any;

  public algorithm: KeyAlgorithm = { name: "" };

  public extractable = false;

  public type: KeyType = "secret";

  public usages: KeyUsage[] = [];
}
