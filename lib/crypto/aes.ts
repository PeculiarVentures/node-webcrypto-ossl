// Core
import { AlgorithmError, AlgorithmNames, Base64Url, BaseCrypto, WebCryptoError } from "webcrypto-core";

// Local
import { CryptoKey } from "../key";
import * as native from "../native";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

export class AesCrypto extends BaseCrypto {

    public static generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<any> {
        return new Promise((resolve, reject) => {
            native.AesKey.generate(algorithm.length / 8, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    const aes = new CryptoKey(key, algorithm, "secret", extractable, keyUsages);
                    resolve(aes);
                }
            });
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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
            (algorithm as any).length = raw.byteLength * 8;
            native.AesKey.import(raw, (err, key) => {
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
            const nativeKey = key.native as native.AesKey;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    const jwk: JsonWebKey = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: "",
                        ext: true,
                    };
                    // set alg
                    jwk.alg = "A" + (key.algorithm as any).length + /-(\w+)$/.exec(key.algorithm.name)![1].toUpperCase();
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
                            resolve(data.buffer);
                        }
                    });
                    break;
                default: throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    public static encrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        if (algorithm.name.toUpperCase() === AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native as native.AesKey, data, true);
        } else {
            return this.EncryptDecrypt(algorithm, key, data, true);
        }
    }

    public static decrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        if (algorithm.name.toUpperCase() === AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native as native.AesKey, data, false);
        } else {
            return this.EncryptDecrypt(algorithm, key, data, false);
        }
    }

    protected static EncryptDecrypt(algorithm: AesCbcParams | AesGcmParams, key: CryptoKey, data: Buffer, type: boolean): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native as native.AesKey;
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.AesGCM.toLowerCase(): {
                    const algGCM = algorithm as AesGcmParams;
                    const iv = new Buffer(algorithm.iv as Uint8Array);
                    const aad = algGCM.additionalData ? new Buffer(algGCM.additionalData as Uint8Array) : new Buffer(0);
                    const tagLength = algGCM.tagLength || 128;
                    if (type) {
                        nativeKey.encryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    } else {
                        nativeKey.decryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case AlgorithmNames.AesCBC.toLowerCase(): {
                    const algCBC = "CBC";
                    const iv = new Buffer(algorithm.iv as Uint8Array);
                    if (type) {
                        nativeKey.encrypt(algCBC, iv, data, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    } else {
                        nativeKey.decrypt(algCBC, iv, data, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case AlgorithmNames.AesCTR.toLowerCase(): {
                    const alg: AesCtrParams = algorithm as any;
                    const counter = new Buffer(alg.counter as Uint8Array);
                    if (type) {
                        nativeKey.encryptCtr(data, counter, alg.length, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    } else {
                        nativeKey.decryptCtr(data, counter, alg.length, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case AlgorithmNames.AesECB.toLowerCase(): {
                    if (type) {
                        nativeKey.encryptEcb(data, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    } else {
                        nativeKey.decryptEcb(data, (err, data2) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                default: throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algorithm.name);
            }
        });
    }

    /**
     * Wrap/Unwrap function for AES-KW
     * 
     * @protected
     * @param {native.AesKey} key Native key
     * @param {Buffer} data Incoming data
     * @param {boolean} enc Type of operation. `true` - wrap, `false` - unwrap
     * @returns
     * 
     * @memberOf AesCrypto
     */
    protected static WrapUnwrap(key: native.AesKey, data: Buffer, enc: boolean) {
        return new Promise((resolve, reject) => {
            const fn = enc ? key.wrapKey : key.unwrapKey;

            fn.call(key, data, (err: Error, data2: Buffer) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(data2);
                }
            });
        });
    }

}
