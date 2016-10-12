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

export class AesCrypto extends BaseCrypto {

    static generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<any> {
        return new Promise((resolve, reject) => {
            native.AesKey.generate(algorithm.length / 8, (err, key) => {
                if (err) reject(err);
                else {
                    let aes = new CryptoKey(key, algorithm, "secret", extractable, keyUsages);
                    resolve(aes);
                }
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
            let nkey = key.native as native.AesKey;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    let jwk: JsonWebKey = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: "",
                        ext: true
                    };
                    // set alg
                    jwk.alg = "A" + (key.algorithm as any).length + /-(\w+)$/.exec(key.algorithm.name) ![1];
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
                default: throw new WebCryptoError(`ExportKey: Unknown export frmat '${format}'`);
            }
        });
    }

    protected static EncryptDecrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer, type: boolean): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let nkey = key.native as native.AesKey;
            const iv = new Buffer(algorithm.iv as Uint8Array);
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.AesGCM.toLowerCase():
                    const _algGCM = algorithm as AesGcmParams;
                    const aad = _algGCM.additionalData ? new Buffer(_algGCM.additionalData as Uint8Array) : new Buffer(0);
                    const tagLength = _algGCM.tagLength || 128;
                    if (type) {
                        nkey.encryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data) => {
                            if (err) reject(err);
                            else
                                resolve(data.buffer);
                        });
                    }
                    else {
                        nkey.decryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data) => {
                            if (err) reject(err);
                            else
                                resolve(data.buffer);
                        });
                    }
                    break;
                case AlgorithmNames.AesCBC.toLowerCase():
                    const _algCBC = "CBC";
                    if (type)
                        nkey.encrypt(_algCBC, iv, data, (err, data) => {
                            if (err) reject(err);
                            else
                                resolve(data.buffer);
                        });
                    else
                        nkey.decrypt(_algCBC, iv, data, (err, data) => {
                            if (err) reject(err);
                            else
                                resolve(data.buffer);
                        });

                    break;
                default: throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algorithm.name);
            }
        });
    }

    static encrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, true);
    }

    static decrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, false);
    }
}