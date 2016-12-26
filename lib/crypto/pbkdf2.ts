// Core
import * as Core from "webcrypto-core";

// Local
import { CryptoKey } from "../key";
import { AesCrypto } from "./aes";
import { HmacCrypto } from "./hmac";
import * as native from "../native";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Core.Base64Url.decode(b64url));
}

export class Pbkdf2Crypto extends Core.BaseCrypto {

    static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let _format = format.toLocaleLowerCase();
            let _alg = algorithm as any;
            _alg.name = _alg.name.toUpperCase();
            let raw: Buffer;
            switch (_format) {
                case "jwk":
                    raw = b64_decode((keyData as JsonWebKey).k!);
                    break;
                case "raw":
                    raw = keyData as Buffer;
                    break;
                default:
                    throw new Core.WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            _alg.length = raw.byteLength * 8;
            native.Pbkdf2Key.importKey(raw, (err, key) => {
                if (err) reject(err);
                else
                    resolve(new CryptoKey(key, algorithm as Algorithm, "secret", extractable, keyUsages));
            });
        });
    }

    static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                return this.deriveBits(algorithm, baseKey, (derivedKeyType as any).length);
            })
            .then(raw => {
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
                return CryptoClass.importKey("raw", new Buffer(raw), derivedKeyType, extractable, keyUsages);
            });
    }

    static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const _algorithm = algorithm as Pbkdf2Params;
            const hash = Core.PrepareAlgorithm(_algorithm.hash);
            const salt = new Buffer(Core.PrepareData(_algorithm.salt, "salt"));
            // derive bits
            (<native.Pbkdf2Key>baseKey.native).deriveBits(this.wc2ssl(hash), salt, _algorithm.iterations, length, (err, raw) => {
                if (err) reject(err);
                else
                    resolve(raw.buffer);
            });
        });
    }

    static wc2ssl(alg: Algorithm) {
        let _alg = (alg as any).name.toUpperCase().replace("-", "");
        return _alg;
    }
}
