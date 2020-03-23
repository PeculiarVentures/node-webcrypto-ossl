import { AsymmetricKey } from "../../keys/asymmetric";

export class RsaPublicKey extends AsymmetricKey {
  public readonly type: "public" = "public";
  public algorithm!: RsaHashedKeyAlgorithm;
}
