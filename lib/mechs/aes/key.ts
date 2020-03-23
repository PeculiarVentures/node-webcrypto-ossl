import { SymmetricKey } from "../../keys";

export class AesCryptoKey extends SymmetricKey {
  public algorithm!: AesKeyAlgorithm;
}
