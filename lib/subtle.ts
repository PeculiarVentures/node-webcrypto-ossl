// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
let BaseCrypto = webcrypto.BaseCrypto;
const AlgorithmNames = webcrypto.AlgorithmNames;

// Local
import * as native from "./native";
import { CryptoKey } from "./key";
// import * as alg from "./alg";
import * as rsa from "./rsa";
import * as aes from "./aes";
// import * as ec from "./ec";

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
    generateKey(algorithm: any, extractable: boolean, keyUsages: string[]) {
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
                        AlgClass = aes.AesCrypto;
                        break;
                    // case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    //     AlgClass = ec.Ecdsa;
                    //     break;
                    // case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    //     AlgClass = ec.Ecdh;
                    //     break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.generateKey(_alg as any, extractable, keyUsages);
            });
    }

    sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
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
                    // case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    //     AlgClass = ec.Ecdsa;
                    //     break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.sign(_alg, key, _data);
            });
    }

    verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean> {
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
                    // case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    //     AlgClass = ec.Ecdsa;
                    //     break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.verify(_alg, key, _signature, _data);
            });
    }

    encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
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
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.encrypt(_alg, key, _data);
            });
    }

    decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
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
                        let _data: Buffer;
                        if (!(exportedKey instanceof ArrayBuffer)) {
                            _data = new Buffer(JSON.stringify(exportedKey));
                        }
                        else {
                            _data = new Buffer(exportedKey);
                        }
                        return this.encrypt(wrapAlgorithm, wrappingKey, _data);
                    });
            });
    }

    unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
                return Promise.resolve()
                    .then(() => {
                        return this.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
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


    // deriveKey(algorithm: NodeAlgorithm, baseKey: CryptoKey, derivedKeyType: NodeAlgorithm, extractable: boolean, keyUsages: string[]) {
    //     let that = this;

    //     return new Promise<NodeCryptoKey>((resolve, reject) => {
    //         let _alg1 = PrepareAlgorithm(algorithm);
    //         let _alg2 = PrepareAlgorithm(derivedKeyType);

    //         let AlgClass: alg.IAlgorithmBase = null;
    //         switch (_alg1.name.toLowerCase()) {
    //             case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
    //                 AlgClass = ec.Ecdh;
    //                 break;
    //             default:
    //                 throw new TypeError("Unsupported algorithm in use");
    //         }
    //         AlgClass.deriveKey(_alg1, baseKey, _alg2, extractable, keyUsages, function (err, key) {
    //             if (err)
    //                 reject(err);
    //             else
    //                 resolve(key);
    //         });
    //     });
    // }

    // deriveBits(algorithm: NodeAlgorithm, baseKey: CryptoKey, length: number) {
    //     let that = this;

    //     return new Promise<ArrayBuffer>((resolve, reject) => {
    //         let _alg = PrepareAlgorithm(algorithm);

    //         let AlgClass: alg.IAlgorithmBase = null;
    //         switch (_alg.name.toLowerCase()) {
    //             case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
    //                 AlgClass = ec.Ecdh;
    //                 break;
    //             default:
    //                 throw new TypeError("Unsupported algorithm in use");
    //         }
    //         AlgClass.deriveBits(_alg, baseKey, length, (err, dbits) => {
    //             if (err)
    //                 reject(err);
    //             else
    //                 resolve(dbits.buffer);
    //         });
    //     });
    // }

    exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
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
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, key.algorithm.name);
                }
                return AlgClass.exportKey(format, key);
            });
    }

    importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
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
                        AlgClass = aes.AesCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.importKey(format, _data, _alg, extractable, keyUsages);
            });
    }

}