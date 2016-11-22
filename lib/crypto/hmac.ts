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

    protected static getHashSize(hashName: string) {
        switch (hashName) {
            case AlgorithmNames.Sha1:
                return 128;
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

    static generateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            native.HmacKey.generate(algorithm.length || this.getHashSize((algorithm.hash as Algorithm).name), (err, key) => {
                if (err) reject(err);
                else
                    resolve(new CryptoKey(key, algorithm, "secret", extractable, keyUsages));
            });
        });
    }

    static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let _format = format.toLocaleLowerCase();
            let raw: Buffer;
            switch (_format) {
                case "jwk":
                    raw = b64_decode((keyData as JsonWebKey).k!);
                    break;
                case "raw":
                    raw = keyData as Buffer;
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            native.AesKey.import(raw, (err, key) => {
                if (err) reject(err);
                else
                    resolve(new CryptoKey(key, algorithm as Algorithm, "secret", extractable, keyUsages));
            });
        });
    }

    static exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    static exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let nkey = key.native as native.HmacKey;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    let jwk: JsonWebKey = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["sign", "verify"],
                        k: "",
                        ext: true
                    };
                    // set alg
                    jwk.alg = "HS" + /-(\d+)$/.exec((key.algorithm as any).hash.name) ![1];
                    nkey.export((err, data) => {
                        if (err) reject(err);
                        else {
                            jwk.k = Base64Url.encode(data);
                            resolve(jwk);
                        }
                    });
                    break;
                case "raw":
                    nkey.export((err, data) => {
                        if (err) reject(err);
                        else
                            resolve(data.buffer);
                    });
                    break;
                default: throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.sign(_alg, data, (err, signature) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else {
                    resolve(signature.buffer);
                }
            });
        });
    }

    static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.verify(_alg, data, signature, (err, res) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else
                    resolve(res);
            });
        });
    }

    static wc2ssl(alg: any) {
        let _alg = (alg.hash as Algorithm).name.toUpperCase().replace("-", "");
        return _alg;
    }
}
