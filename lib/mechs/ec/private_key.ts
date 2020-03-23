import { AsymmetricKey } from "../../keys";

export class EcPrivateKey extends AsymmetricKey {
  public readonly type: "private" = "private";
  public algorithm!: EcKeyAlgorithm;
}
