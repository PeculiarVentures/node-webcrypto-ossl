import { CryptoKey } from "./key";

export class SymmetricKey extends CryptoKey {
  public readonly type: "secret" = "secret";
}
