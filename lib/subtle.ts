// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
let BaseCrypto = webcrypto.BaseCrypto;
const AlgorithmNames = webcrypto.AlgorithmNames;

// Local
import * as native from "./native";
import { CryptoKey, CryptoKeyPair } from "./key";
// import * as alg from "./alg";
import * as rsa from "./crypto/rsa";
import * as aes from "./crypto/aes";
import * as ec from "./crypto/ec";
import * as hmac from "./crypto/hmac";
import * as pbkdf2 from "./crypto/pbkdf2";

/**
 * Prepare array of data before it's using 
 * @param data Array which must be prepared
 */
function PrepareData(data: NodeBufferSource): Buffer {
    return ab2b(data);
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(ab: NodeBufferSource) {
    return new Buffer(ab as any);
}

/**
 * Converts Buffer to ArrayBuffer
 * @param b Buffer value wich must be converted to ArrayBuffer
 */
// function b2ab(b: Buffer): ArrayBuffer {
//     return b.buffer;
// }

export class SubtleCrypto extends webcrypto.SubtleCrypto {
    /**
     * Computes a digest
     * 
     * > Note: Has difference from W3 WebcCrypto API
     * > - Supports Buffer
     * > - Supports SHA-1, SHA-224, SAH-256, SHA-384, SHA-512 algorithms 
     * 
     * @param {AlgorithmIdentifier} algorithm
     * @param {NodeSourceBuffer} data
     * @returns {PromiseLike<ArrayBuffer>}
     * 
     * @memberOf SubtleCrypto
     */
    digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.digest.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const _alg = PrepareAlgorithm(algorithm);
                    const _data = PrepareData(data);
                    let algName = _alg.name.toLowerCase();
                    switch (algName) {
                        case "sha-1":
                        case "sha-224":
                        case "sha-256":
                        case "sha-384":
                        case "sha-512":
                            native.Core.digest(algName.replace("-", ""), _data, (err, digest) => {
                                if (err)
                                    reject(err);
                                else
                                    resolve(digest.buffer);
                            });
                            break;
                        default:
                            throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algName);
                    }
                });
            });
    }

    generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
    generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
    generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
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
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.generateKey(_alg as any, extractable, keyUsages);
            });
    }

    sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    sign(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm as string);
                let _data = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.sign(_alg as any, key, _data);
            });
    }

    verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
    verify(algorithm: any, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm as string);
                let _signature = PrepareData(signature);
                let _data = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.verify(_alg as any, key, _signature, _data);
            });
    }

    encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    encrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.encrypt.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm);
                let _data = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.encrypt(_alg, key, _data);
            });
    }

    decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    decrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.decrypt.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm);
                let _data = PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                    case AlgorithmNames.AesKW.toLowerCase():
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.decrypt(_alg, key, _data);
            });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        return super.wrapKey.apply(this, arguments)
            .then(() => {
                return this.exportKey(format as any, key)
                    .then(exportedKey => {
                        let _alg = webcrypto.PrepareAlgorithm(wrapAlgorithm);
                        let _data: Buffer;
                        if (!(exportedKey instanceof ArrayBuffer)) {
                            _data = new Buffer(JSON.stringify(exportedKey));
                        }
                        else {
                            _data = new Buffer(exportedKey);
                        }
                        let CryptoClass: typeof BaseCrypto | undefined;
                        if (_alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW)
                            CryptoClass = aes.AesCrypto;

                        if (CryptoClass)
                            return CryptoClass.encrypt(_alg, wrappingKey, _data);
                        else
                            return this.encrypt(_alg, wrappingKey, _data);
                    });
            });
    }

    unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
                return Promise.resolve()
                    .then(() => {
                        let _alg = webcrypto.PrepareAlgorithm(unwrapAlgorithm);
                        let _data = PrepareData(wrappedKey);

                        let CryptoClass: typeof BaseCrypto | undefined;
                        if (_alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW)
                            CryptoClass = aes.AesCrypto;

                        if (CryptoClass)
                            return CryptoClass.decrypt(_alg, unwrappingKey, _data);
                        else
                            return this.decrypt(_alg, unwrappingKey, _data);
                    })
                    .then(decryptedKey => {
                        let keyData: JsonWebKey | Buffer;
                        if (format === "jwk") {
                            keyData = JSON.parse(new Buffer(decryptedKey).toString());
                        }
                        else {
                            keyData = new Buffer(decryptedKey);
                        }
                        return this.importKey(format as any, keyData as Buffer, unwrappedKeyAlgorithm, extractable, keyUsages);
                    });
            });
    }

    deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    deriveKey(algorithm: any, baseKey: CryptoKey, derivedKeyType: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.deriveKey.apply(this, arguments)
            .then(() => {
                let _algorithm = PrepareAlgorithm(algorithm);
                let _derivedKeyType = PrepareAlgorithm(derivedKeyType);

                let AlgClass: typeof BaseCrypto;
                switch (_algorithm.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Pbkdf2.toLowerCase():
                        AlgClass = pbkdf2.Pbkdf2Crypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _algorithm.name);
                }
                return AlgClass.deriveKey(_algorithm as any, baseKey, _derivedKeyType, extractable, keyUsages);
            });
    }

    deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    deriveBits(algorithm: any, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
                let _algorithm = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (_algorithm.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    case AlgorithmNames.Pbkdf2.toLowerCase():
                        AlgClass = pbkdf2.Pbkdf2Crypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _algorithm.name);
                }
                return AlgClass.deriveBits(_algorithm as any, baseKey, length);
            });
    }

    exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
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
                    case AlgorithmNames.AesCBC.toLowerCase():
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

    importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.importKey.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm as string);

                let _data = keyData;
                if (format !== "jwk") {
                    _data = PrepareData(_data as NodeBufferSource);
                }

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
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
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.importKey(format, _data, _alg, extractable, keyUsages);
            });
    }

}