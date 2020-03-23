import { AsymmetricKey } from "../../keys";

export class RsaPrivateKey extends AsymmetricKey {
  public readonly type: "private" = "private";
  public algorithm!: RsaHashedKeyAlgorithm;
}
