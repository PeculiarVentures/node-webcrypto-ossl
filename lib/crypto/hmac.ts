// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const BaseCrypto = webcrypto.BaseCrypto;
const Base64Url = webcrypto.Base64Url;

// Local
import { CryptoKey } from "../key";
import * as native from "../native";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

export class HmacCrypto extends BaseCrypto {

    public static generateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const length = algorithm.length || this.getHashSize((algorithm.hash as Algorithm).name);
            native.HmacKey.generate(length, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(new CryptoKey(key, algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            let raw: Buffer;
            switch (formatLC) {
                case "jwk":
                    raw = b64_decode((keyData as JsonWebKey).k!);
                    break;
                case "raw":
                    raw = keyData as Buffer;
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            native.HmacKey.import(raw, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(new CryptoKey(key, algorithm as Algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    }

    public static exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    public static exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native as native.HmacKey;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    const jwk: JsonWebKey = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["sign", "verify"],
                        k: "",
                        ext: true,
                    };
                    // set alg
                    jwk.alg = "HS" + /-(\d+)$/.exec((key.algorithm as any).hash.name) ![1];
                    nativeKey.export((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            jwk.k = Base64Url.encode(data);
                            resolve(jwk);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.export((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data.buffer as ArrayBuffer);
                        }
                    });
                    break;
                default: throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    public static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.sign(alg, data, (err, signature) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(signature.buffer as ArrayBuffer);
                }
            });
        });
    }

    public static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.verify(alg, data, signature, (err, res) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(res);
                }
            });
        });
    }

    public static wc2ssl(algorithm: any) {
        const alg = (algorithm.hash as Algorithm).name.toUpperCase().replace("-", "");
        return alg;
    }

    protected static getHashSize(hashName: string) {
        switch (hashName) {
            case AlgorithmNames.Sha1:
                return 160;
            case AlgorithmNames.Sha256:
                return 256;
            case AlgorithmNames.Sha384:
                return 384;
            case AlgorithmNames.Sha512:
                return 512;
            default:
                throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, hashName);
        }
    }
}
