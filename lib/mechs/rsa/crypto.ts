import * as native from "native";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey, CryptoKeyStorage } from "../../keys";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaCrypto {

  public static publicKeyUsages = ["verify", "encrypt", "wrapKey"];
  public static privateKeyUsages = ["sign", "decrypt", "unwrapKey"];

  public static async generateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]): Promise<CryptoKeyPair> {
    return new Promise((resolve, reject) => {
      const size = algorithm.modulusLength;
      const exp = Buffer.from(algorithm.publicExponent);
      // convert exp
      let nExp: number = 0;
      if (exp.length === 3) {
        nExp = 1;
      }
      native.Key.generateRsa(size, nExp, (err, key) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Rsa: Can not generate new key\n${err.message}`));
          } else {
            const prvUsages = ["sign", "decrypt", "unwrapKey"]
              .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage)) as KeyUsage[];
            const pubUsages = ["verify", "encrypt", "wrapKey"]
              .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage)) as KeyUsage[];

            const privateKey = RsaPrivateKey.create(algorithm, "private", extractable, prvUsages);
            const publicKey = RsaPublicKey.create(algorithm, "public", true, pubUsages);
            privateKey.native = publicKey.native = key;

            resolve({
              privateKey: CryptoKeyStorage.setItem(privateKey),
              publicKey: CryptoKeyStorage.setItem(publicKey),
            });
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public static async exportKey(format: KeyFormat, key: core.CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const nativeKey = CryptoKeyStorage.getItem(key).native as native.Key;
      const type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
      switch (format.toLocaleLowerCase()) {
        case "jwk":
          nativeKey.exportJwk(type, (err, data) => {
            if (err) {
              throw new core.CryptoError(`Cannot export JWK key\n${err}`);
            }
            try {
              const jwk: JsonWebKey = {
                kty: "RSA",
                ext: true,
                alg: this.getJwkAlgorithm(key.algorithm as RsaHashedKeyAlgorithm),
               };
              jwk.key_ops = key.usages;

              jwk.e = Convert.ToBase64Url(data.e);
              jwk.n = Convert.ToBase64Url(data.n);
              if (key.type === "private") {
                jwk.d = Convert.ToBase64Url(data.d);
                jwk.p = Convert.ToBase64Url(data.p);
                jwk.q = Convert.ToBase64Url(data.q);
                jwk.dp = Convert.ToBase64Url(data.dp);
                jwk.dq = Convert.ToBase64Url(data.dq);
                jwk.qi = Convert.ToBase64Url(data.qi);
              }
              resolve(jwk);
            } catch (e) {
              reject(e);
            }
          });
          break;
        case "spki":
          nativeKey.exportSpki((err, raw) => {
            if (err) {
              reject(err);
            } else {
              resolve(core.BufferSourceConverter.toArrayBuffer(raw));
            }
          });
          break;
        case "pkcs8":
          nativeKey.exportPkcs8((err, raw) => {
            if (err) {
              reject(err);
            } else {
              resolve(core.BufferSourceConverter.toArrayBuffer(raw));
            }
          });
          break;
        default:
          throw new core.CryptoError(`ExportKey: Unknown export format '${format}'`);
      }
    });
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    let keyType = native.KeyType.PUBLIC;
    return new Promise<native.Key>((resolve, reject) => {
      const formatLC = format.toLocaleLowerCase();
      switch (formatLC) {
        case "jwk":
          const jwk = keyData as JsonWebKey;
          const data: { [key: string]: Buffer } = {};
          // prepare data
          data["kty"] = jwk.kty as any;
          data["n"] = Buffer.from(Convert.FromBase64Url(jwk.n!));
          data["e"] = Buffer.from(Convert.FromBase64Url(jwk.e!));
          if (jwk.d) {
            keyType = native.KeyType.PRIVATE;
            data["d"] = Buffer.from(Convert.FromBase64Url(jwk.d!));
            data["p"] = Buffer.from(Convert.FromBase64Url(jwk.p!));
            data["q"] = Buffer.from(Convert.FromBase64Url(jwk.q!));
            data["dp"] = Buffer.from(Convert.FromBase64Url(jwk.dp!));
            data["dq"] = Buffer.from(Convert.FromBase64Url(jwk.dq!));
            data["qi"] = Buffer.from(Convert.FromBase64Url(jwk.qi!));
          }
          native.Key.importJwk(data, keyType, (err, key) => {
            try {
              if (err) {
                reject(new core.CryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
              } else {
                resolve(key);
              }
            } catch (e) {
              reject(e);
            }
          });
          break;
        case "pkcs8":
        case "spki":
          let importFunction = native.Key.importSpki;
          if (formatLC === "pkcs8") {
            keyType = native.KeyType.PRIVATE;
            importFunction = native.Key.importPkcs8;
          }
          importFunction(Buffer.from(keyData), (err, key) => {
            try {
              if (err) {
                reject(new core.CryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
              } else {
                resolve(key);
              }
            } catch (e) {
              reject(e);
            }
          });
          break;
        default:
          throw new core.CryptoError(`ImportKey: Wrong format value '${format}'`);
      }
    })
      .then((key) => {
        const alg: RsaHashedKeyAlgorithm = {
          ...algorithm,
          modulusLength: key.modulusLength() << 3,
          publicExponent: new Uint8Array(key.publicExponent()),
          hash: algorithm.hash as Algorithm,
        };
        const Key: typeof CryptoKey = keyType
          ? RsaPrivateKey
          : RsaPublicKey;
        const rsaKey = Key.create(alg, keyType ? "private" : "public", extractable, keyUsages);
        rsaKey.native = key;
        return CryptoKeyStorage.setItem(rsaKey);
      });
  }

  public static checkCryptoKey(key: any): asserts key is RsaPublicKey | RsaPrivateKey {
    if (!(key instanceof RsaPrivateKey || key instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

  public static  getJwkAlgorithm(algorithm: RsaHashedKeyAlgorithm) {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP": {
        const mdSize = /(\d+)$/.exec(algorithm.hash.name)![1];
        return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
      }
      case "RSASSA-PKCS1-V1_5":
        return `RS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSA-PSS":
        return `PS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

}
