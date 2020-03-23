import * as native from "native";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey, CryptoKeyStorage } from "../../keys";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

function buf_pad(buf: Buffer, padSize: number = 0) {
  if (padSize && Buffer.length < padSize) {
    const pad = Buffer.from(new Uint8Array(padSize - buf.length).map((v) => 0));
    return Buffer.concat([pad, buf]);
  }
  return buf;
}

export class EcCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return new Promise((resolve, reject) => {
      const alg = algorithm as EcKeyGenParams;
      const namedCurve = this.getNamedCurve(alg.namedCurve);

      native.Key.generateEc(namedCurve, (err, key) => {
        if (err) {
          reject(err);
        } else {
          const prvUsages = ["sign", "deriveKey", "deriveBits"]
            .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage)) as KeyUsage[];
          const pubUsages = ["verify"]
            .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage)) as KeyUsage[];
          const privateKey = EcPrivateKey.create(algorithm, "private", extractable, prvUsages);
          const publicKey = EcPublicKey.create(algorithm, "public", true, pubUsages);
          publicKey.native = privateKey.native = key;
          resolve({
            privateKey: CryptoKeyStorage.setItem(privateKey),
            publicKey: CryptoKeyStorage.setItem(publicKey),
          });
        }
      });
    });
  }

  public static async exportKey(format: KeyFormat, key: core.NativeCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
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
              const jwk: JsonWebKey = { kty: "EC", ext: true };
              jwk.crv = (key.algorithm as EcKeyAlgorithm).namedCurve;
              jwk.key_ops = key.usages;
              let padSize = 0;
              switch (jwk.crv) {
                case "P-256":
                case "K-256":
                  padSize = 32;
                  break;
                case "P-384":
                  padSize = 48;
                  break;
                case "P-521":
                  padSize = 66;
                  break;
                default:
                  throw new Error(`Unsupported named curve '${jwk.crv}'`);
              }
              jwk.x = Convert.ToBase64Url(buf_pad(data.x, padSize));
              jwk.y = Convert.ToBase64Url(buf_pad(data.y, padSize));
              if (key.type === "private") {
                jwk.d = Convert.ToBase64Url(buf_pad(data.d, padSize));
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
        case "raw":
          nativeKey.exportJwk(type, (err, data) => {
            if (err) {
              reject(err);
            } else {
              let padSize = 0;

              const crv = (key.algorithm as any).namedCurve;

              switch (crv) {
                case "P-256":
                case "K-256":
                  padSize = 32;
                  break;
                case "P-384":
                  padSize = 48;
                  break;
                case "P-521":
                  padSize = 66;
                  break;
                default:
                  throw new Error(`Unsupported named curve '${crv}'`);
              }

              const x = buf_pad(data.x, padSize);
              const y = buf_pad(data.y, padSize);

              const rawKey = new Uint8Array(1 + x.length + y.length);
              rawKey.set([4]);
              rawKey.set(x, 1);
              rawKey.set(y, 1 + x.length);

              resolve(core.BufferSourceConverter.toArrayBuffer(rawKey));
            }
          });
          break;
        default:
          throw new core.CryptoError(`ExportKey: Unknown export format '${format}'`);
      }
    });
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    return new Promise((resolve, reject) => {
      const formatLC = format.toLocaleLowerCase();
      const data: { [key: string]: Buffer } = {};
      let keyType = native.KeyType.PUBLIC;
      switch (formatLC) {
        case "raw": {
          let keyLength = 0;
          const rawData = Buffer.from(keyData);

          if (rawData.byteLength === 65) {
            // P-256
            // Key length 32 Byte
            keyLength = 32;
          } else if (rawData.byteLength === 97) {
            // P-384
            // Key length 48 Byte
            keyLength = 48;
          } else if (rawData.byteLength === 133) {
            // P-521
            // Key length: 521/= 65,125 => 66 Byte
            keyLength = 66;
          }

          const x = Buffer.from(rawData).slice(1, keyLength + 1);

          const y = Buffer.from(rawData).slice(keyLength + 1, (keyLength * 2) + 1);

          data["kty"] = Buffer.from("EC", "utf-8");
          data["crv"] = this.getNamedCurve(algorithm.namedCurve.toUpperCase());
          data["x"] = buf_pad(x, keyLength);
          data["y"] = buf_pad(y, keyLength);

          native.Key.importJwk(data, keyType, (err, key) => {
            try {
              if (err) {
                reject(new core.CryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
              } else {
                const ecKey = EcPublicKey.create(algorithm, "public", extractable, keyUsages);
                ecKey.native = key;
                resolve(CryptoKeyStorage.setItem(ecKey));
              }
            } catch (e) {
              reject(e);
            }
          });

          break;
        }
        case "jwk": {
          const jwk = keyData as JsonWebKey;
          // prepare data
          data["kty"] = jwk.kty as any;
          data["crv"] = this.getNamedCurve(jwk.crv!);
          data["x"] = Buffer.from(Convert.FromBase64Url(jwk.x!));
          data["y"] = Buffer.from(Convert.FromBase64Url(jwk.y!));
          if (jwk.d) {
            keyType = native.KeyType.PRIVATE;
            data["d"] = Buffer.from(Convert.FromBase64Url(jwk.d!));
          }
          native.Key.importJwk(data, keyType, (err, key) => {
            try {
              if (err) {
                reject(new core.CryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
              } else {
                const Key: typeof CryptoKey = jwk.d ? EcPrivateKey : EcPublicKey;
                const ecKey = Key.create(algorithm, jwk.d ? "private" : "public", extractable, keyUsages);
                ecKey.native = key;
                resolve(CryptoKeyStorage.setItem(ecKey));
              }
            } catch (e) {
              reject(e);
            }
          });
          break;
        }
        case "pkcs8":
        case "spki": {
          let importFunction = native.Key.importPkcs8;
          if (formatLC === "spki") {
            importFunction = native.Key.importSpki;
          }
          const rawData = Buffer.from(keyData);
          importFunction(rawData, (err, key) => {
            try {
              if (err) {
                reject(new core.CryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
              } else {
                const Key: typeof CryptoKey = formatLC === "pkcs8" ? EcPrivateKey : EcPublicKey;
                const ecKey = Key.create(algorithm, formatLC === "pkcs8" ? "private" : "public", extractable, keyUsages);
                ecKey.native = key;
                resolve(CryptoKeyStorage.setItem(ecKey));
              }
            } catch (e) {
              reject(e);
            }
          });
          break;
        }
        default:
          throw new core.CryptoError(`ImportKey: Wrong format value '${format}'`);
      }
    });
  }

  public static checkCryptoKey(key: any): asserts key is EcPublicKey | EcPrivateKey {
    if (!(key instanceof EcPrivateKey || key instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  private static getNamedCurve(namedCurve: string) {
    switch (namedCurve.toUpperCase()) {
      case "P-192":
        namedCurve = "secp192r1";
        break;
      case "P-256":
        namedCurve = "secp256r1";
        break;
      case "P-384":
        namedCurve = "secp384r1";
        break;
      case "P-521":
        namedCurve = "secp521r1";
        break;
      case "K-256":
        namedCurve = "secp256k1";
        break;
      default:
        throw new core.CryptoError("Unsupported namedCurve in use");
    }
    return (native.EcNamedCurves as any)[namedCurve];
  }

}
