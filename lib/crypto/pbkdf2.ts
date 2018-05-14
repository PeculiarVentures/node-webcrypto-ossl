// Core
import * as Core from "webcrypto-core";

// Local
import { CryptoKey } from "../key";
import * as native from "../native";
import { AesCrypto } from "./aes";
import { HmacCrypto } from "./hmac";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Core.Base64Url.decode(b64url));
}

export class Pbkdf2Crypto extends Core.BaseCrypto {

    public static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            const alg = algorithm as any;
            alg.name = alg.name.toUpperCase();
            let raw: Buffer;
            switch (formatLC) {
                case "jwk":
                    raw = b64_decode((keyData as JsonWebKey).k!);
                    break;
                case "raw":
                    raw = keyData as Buffer;
                    break;
                default:
                    throw new Core.WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            alg.length = raw.byteLength * 8;
            native.Pbkdf2Key.importKey(raw, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(new CryptoKey(key, algorithm as Algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    }

    public static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]) {
        return Promise.resolve()
            .then(() => {
                return this.deriveBits(algorithm, baseKey, (derivedKeyType as any).length);
            })
            .then((raw) => {
                let CryptoClass: typeof Core.BaseCrypto;
                switch (derivedKeyType.name.toUpperCase()) {
                    case Core.AlgorithmNames.AesCBC:
                    case Core.AlgorithmNames.AesGCM:
                    case Core.AlgorithmNames.AesKW:
                        CryptoClass = AesCrypto;
                        break;
                    case Core.AlgorithmNames.Hmac:
                        CryptoClass = HmacCrypto;
                        break;
                    default:
                        throw new Core.AlgorithmError(Core.AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
                return CryptoClass.importKey("raw", new Buffer(raw), derivedKeyType as any, extractable, keyUsages);
            });
    }

    public static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = algorithm as Pbkdf2Params;
            const nativeKey = baseKey.native as native.Pbkdf2Key;
            const hash = Core.PrepareAlgorithm(alg.hash);
            const salt = new Buffer(Core.PrepareData(alg.salt!, "salt"));
            // derive bits
            nativeKey.deriveBits(this.wc2ssl(hash), salt, alg.iterations, length, (err, raw) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(raw.buffer as ArrayBuffer);
                }
            });
        });
    }

    public static wc2ssl(algorithm: Algorithm) {
        const alg = (algorithm as any).name.toUpperCase().replace("-", "");
        return alg;
    }
}
