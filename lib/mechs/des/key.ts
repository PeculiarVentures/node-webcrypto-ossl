import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { SymmetricKey } from "../../keys";

export class DesCryptoKey extends SymmetricKey {
  public algorithm!: core.DesKeyAlgorithm;

  public toJSON() {
    return {
      kty: "oct",
      alg: this.algorithm.name === "DES-CBC"
        ? this.algorithm.name
        : "3DES-CBC",
      ext: true,
      k: Convert.ToBase64Url(this.native),
      key_ops: this.usages,
    };
  }
}
