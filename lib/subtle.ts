// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
const BaseCrypto = webcrypto.BaseCrypto;
const AlgorithmNames = webcrypto.AlgorithmNames;

// Local
import * as aes from "./crypto/aes";
import * as ec from "./crypto/ec";
import * as hmac from "./crypto/hmac";
import * as pbkdf2 from "./crypto/pbkdf2";
import * as rsa from "./crypto/rsa";
import { CryptoKey, CryptoKeyPair } from "./key";
import * as native from "./native";

/**
 * Prepare array of data before it's using 
 * @param data Array which must be prepared
 */
function PrepareData(data: NodeBufferSource): Buffer {
    return ab2b(data);
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value which must be converted to Buffer
 */
function ab2b(ab: NodeBufferSource) {
    if (Buffer.isBuffer(ab)) {
        return ab;
    } else if (ArrayBuffer.isView(ab)) {
        // NOTE: ab.buffer can have another size than view after ArrayBufferView.subarray
        return Buffer.from(ab.buffer as ArrayBuffer, ab.byteOffset, ab.byteLength);
    } else {
        return Buffer.from(ab);
    }
}

/**
 * Converts Buffer to ArrayBuffer
 * @param b Buffer value which must be converted to ArrayBuffer
 */
// function b2ab(b: Buffer): ArrayBuffer {
//     return b.buffer;
// }

export class SubtleCrypto extends webcrypto.SubtleCrypto {
    /**
     * Computes a digest
     * 
     * > Note: Has difference from W3 WebCrypto API
     * > - Supports Buffer
     * > - Supports SHA-1, SHA-224, SAH-256, SHA-384, SHA-512 algorithms 
     * 
     * @param {AlgorithmIdentifier} algorithm
     * @param {NodeSourceBuffer} data
     * @returns {PromiseLike<ArrayBuffer>}
     * 
     * @memberOf SubtleCrypto
     */
    public digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.digest.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const alg = PrepareAlgorithm(algorithm);
                    const dataBytes = PrepareData(data);
                    const algName = alg.name.toLowerCase();
                    switch (algName) {
                        case "sha-1":
                        case "sha-224":
                        case "sha-256":
                        case "sha-384":
                        case "sha-512":
                            native.Core.digest(algName.replace("-", ""), dataBytes, (err, digest) => {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve(digest.buffer);
                                }
                            });
                            break;
                        default:
                            throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algName);
                    }
                });
            });
    }

    public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
    public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
    public generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Hmac.toLowerCase():
                        AlgClass = hmac.HmacCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.generateKey(alg as any, extractable, keyUsages);
            });
    }

    public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public sign(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);
                const dataBytes = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Hmac.toLowerCase():
                        AlgClass = hmac.HmacCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.sign(alg as any, key, dataBytes);
            });
    }

    public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
    public verify(algorithm: any, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);
                const signatureBytes = PrepareData(signature);
                const dataBytes = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Hmac.toLowerCase():
                        AlgClass = hmac.HmacCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.verify(alg as any, key, signatureBytes, dataBytes);
            });
    }

    public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public encrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.encrypt.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const dataBytes = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.encrypt(alg, key, dataBytes);
            });
    }

    public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public decrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.decrypt.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const dataBytes = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.decrypt(alg, key, dataBytes);
            });
    }

    public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        return super.wrapKey.apply(this, arguments)
            .then(() => {
                return this.exportKey(format as any, key)
                    .then((exportedKey) => {
                        const alg = webcrypto.PrepareAlgorithm(wrapAlgorithm);
                        let dataBytes: Buffer;
                        if (!(exportedKey instanceof ArrayBuffer)) {
                            dataBytes = new Buffer(JSON.stringify(exportedKey));
                        } else {
                            dataBytes = new Buffer(exportedKey);
                        }
                        let CryptoClass: typeof BaseCrypto | undefined;
                        if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                            CryptoClass = aes.AesCrypto;
                        }

                        if (CryptoClass) {
                            return CryptoClass.encrypt(alg, wrappingKey, dataBytes);
                        } else {
                            return this.encrypt(alg, wrappingKey, dataBytes);
                        }
                    });
            });
    }

    public unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
                return Promise.resolve()
                    .then(() => {
                        const alg = webcrypto.PrepareAlgorithm(unwrapAlgorithm);
                        const dataBytes = PrepareData(wrappedKey);

                        let CryptoClass: typeof BaseCrypto | undefined;
                        if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                            CryptoClass = aes.AesCrypto;
                        }

                        if (CryptoClass) {
                            return CryptoClass.decrypt(alg, unwrappingKey, dataBytes);
                        } else {
                            return this.decrypt(alg, unwrappingKey, dataBytes);
                        }
                    })
                    .then((decryptedKey) => {
                        let keyData: JsonWebKey | Buffer;
                        if (format === "jwk") {
                            keyData = JSON.parse(new Buffer(decryptedKey).toString());
                        } else {
                            keyData = new Buffer(decryptedKey);
                        }
                        return this.importKey(format as any, keyData as Buffer, unwrappedKeyAlgorithm as string, extractable, keyUsages);
                    });
            });
    }

    public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public deriveKey(algorithm: any, baseKey: CryptoKey, derivedKeyType: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.deriveKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const algDerivedKeyType = PrepareAlgorithm(derivedKeyType);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Pbkdf2.toLowerCase():
                        AlgClass = pbkdf2.Pbkdf2Crypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.deriveKey(alg as any, baseKey, algDerivedKeyType, extractable, keyUsages);
            });
    }

    public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    public deriveBits(algorithm: any, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Pbkdf2.toLowerCase():
                        AlgClass = pbkdf2.Pbkdf2Crypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.deriveBits(alg as any, baseKey, length);
            });
    }

    public exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey.apply(this, arguments)
            .then(() => {
                let AlgClass: typeof BaseCrypto;
                switch (key.algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Hmac.toLowerCase():
                        AlgClass = hmac.HmacCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, key.algorithm.name);
                }
                return AlgClass.exportKey(format, key);
            });
    }

    public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.importKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);

                let dataAny = keyData;
                if (format !== "jwk") {
                    dataAny = PrepareData(dataAny as NodeBufferSource);
                }

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesCTR.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Hmac.toLowerCase():
                        AlgClass = hmac.HmacCrypto;
                        break;
                    case AlgorithmNames.Pbkdf2.toLowerCase():
                        AlgClass = pbkdf2.Pbkdf2Crypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.importKey(format, dataAny as Buffer, alg as any, extractable, keyUsages);
            });
    }

}
