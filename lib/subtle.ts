// Core
import * as core from "webcrypto-core";
import * as aes from "./mechs/aes";
import * as des from "./mechs/des";
import * as ec from "./mechs/ec";
import * as hmac from "./mechs/hmac";
import * as pbkdf from "./mechs/pbkdf";
import * as rsa from "./mechs/rsa";
import * as sha from "./mechs/sha";
// Local
// import * as pbkdf2 from "./crypto/pbkdf2";
// import { CryptoKey, CryptoKeyPair } from "./key";

export class SubtleCrypto extends core.SubtleCrypto {

  constructor() {
    super();

    //#region AES
    this.providers.set(new aes.AesCbcProvider());
    this.providers.set(new aes.AesCtrProvider());
    this.providers.set(new aes.AesGcmProvider());
    this.providers.set(new aes.AesCmacProvider());
    this.providers.set(new aes.AesKwProvider());
    this.providers.set(new aes.AesEcbProvider());
    //#endregion

    //#region DES
    this.providers.set(new des.DesCbcProvider());
    this.providers.set(new des.DesEde3CbcProvider());
    //#endregion

    //#region RSA
    this.providers.set(new rsa.RsaSsaProvider());
    this.providers.set(new rsa.RsaPssProvider());
    this.providers.set(new rsa.RsaOaepProvider());
    //#endregion

    //#region EC
    this.providers.set(new ec.EcdsaProvider());
    this.providers.set(new ec.EcdhProvider());
    //#endregion

    //#region SHA
    this.providers.set(new sha.Sha1Provider());
    this.providers.set(new sha.Sha256Provider());
    this.providers.set(new sha.Sha384Provider());
    this.providers.set(new sha.Sha512Provider());
    //#endregion

    //#region PBKDF
    this.providers.set(new pbkdf.Pbkdf2Provider());
    //#endregion

    //#region HMAC
    this.providers.set(new hmac.HmacProvider());
    //#endregion

    //#region HKDF
    // this.providers.set(new HkdfProvider());
    //#endregion
  }

}
