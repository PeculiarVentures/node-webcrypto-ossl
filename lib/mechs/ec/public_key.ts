import { AsymmetricKey } from "../../keys/asymmetric";

export class EcPublicKey extends AsymmetricKey {
  public readonly type: "public" = "public";
  public algorithm!: EcKeyAlgorithm;
}
