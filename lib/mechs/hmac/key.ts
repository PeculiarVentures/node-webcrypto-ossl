import { CryptoKey } from "../../keys";

export class HmacCryptoKey extends CryptoKey {
  public algorithm!: HmacKeyAlgorithm;
}
