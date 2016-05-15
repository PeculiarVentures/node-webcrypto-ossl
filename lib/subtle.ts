import {CryptoKey} from "./key";

import * as native from "./native";

import * as alg from "./alg";
import * as rsa from "./rsa";
import * as aes from "./aes";
import * as ec from "./ec";

import * as iwc from "./iwebcrypto";

function prepare_algorithm(alg: iwc.AlgorithmType): iwc.IAlgorithmIdentifier {
    let _alg: iwc.IAlgorithmIdentifier = { name: "" };
    if (typeof alg === "string") {
        _alg = { name: alg };
    }
    else {
        _alg = <iwc.IAlgorithmIdentifier>alg;
    }
    return _alg;
}

/**
 * Prepare array of data before it's using 
 * @param data Array which must be prepared
 */
function prepare_data(data: Buffer | ArrayBuffer): any {
    return (data instanceof ArrayBuffer || data instanceof Uint8Array) ? ab2b(data as ArrayBuffer) : data;
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(ab: ArrayBuffer) {
    let buf = new Uint8Array(ab);
    return new Buffer(buf);
}

/**
 * Converts Buffer to ArrayBuffer
 * @param b Buffer value wich must be converted to ArrayBuffer
 */
function b2ab(b: Buffer): ArrayBuffer {
    return new Uint8Array(b).buffer;
}

declare class Promise {
    constructor(fn: (resolve: Function, reject: Function) => any)
};

export class SubtleCrypto implements SubtleCrypto {

    digest(algorithm: iwc.IAlgorithmIdentifier, data: iwc.TBuffer): any {
        let that = this;
        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);
            let _data = prepare_data(data);

            let algName = _alg.name.toLowerCase();
            switch (algName) {
                case "sha-1":
                case "sha-224":
                case "sha-256":
                case "sha-384":
                case "sha-512":
                    native.Core.digest(algName.replace("-", ""), _data, function (err, digest) {
                        if (err)
                            reject(err);
                        else
                            resolve(new Uint8Array(digest).buffer);
                    });
                    break;
                default:
                    resolve(new Error("AlgorithmIdentifier: Unknown algorithm name"));
            }
        });
    }

    generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): any {
        let that = this;
        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.generateKey(_alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): any {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.sign(_alg, key, _data, function (err, sig) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(sig).buffer);
            });

        });
    }

    verify(algorithm: iwc.AlgorithmType, key: CryptoKey, signature: iwc.TBuffer, data: iwc.TBuffer): any {
        let that = this;
        let _signature = prepare_data(signature);
        let _data = prepare_data(data);

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.verify(_alg, key, _signature, _data, function (err, valid) {
                if (err)
                    reject(err);
                else
                    resolve(valid);
            });
        });
    }

    encrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): any {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.encrypt(_alg, key, _data, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    }

    decrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): any {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.decrypt(_alg, key, _data, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: iwc.IAlgorithmIdentifier): any {
        let that = this;

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.wrapKey(key, wrappingKey, _alg, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    }

    unwrapKey(format: string, wrappedKey: iwc.TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): any {
        let that = this;
        let _wrappedKey = prepare_data(wrappedKey);

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg1 = prepare_algorithm(unwrapAlgorithm);
            let _alg2 = prepare_algorithm(unwrappedAlgorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg1.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.unwrapKey(_wrappedKey, unwrappingKey, _alg1, _alg2, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): any {
        let that = this;

        return new Promise(function (resolve: Function, reject: Function) {
            let _alg1 = prepare_algorithm(algorithm);
            let _alg2 = prepare_algorithm(derivedKeyType);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg1.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.deriveKey(_alg1, baseKey, _alg2, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    deriveBits(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, length: number): any {
        let that = this;

        return new Promise((resolve: Function, reject: Function) => {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.deriveBits(_alg, baseKey, length, (err, dbits) => {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(dbits).buffer);
            });
        });
    }

    exportKey(format: string, key: CryptoKey): any {
        let that = this;

        return new Promise(function (resolve: Function, reject: Function) {
            let KeyClass: any;
            switch (key.algorithm.name) {
                case rsa.RsaPKCS1.ALGORITHM_NAME:
                    KeyClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME:
                    KeyClass = rsa.RsaOAEP;
                    break;
                case aes.AesCBC.ALGORITHM_NAME:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.AesGCM.ALGORITHM_NAME:
                    KeyClass = aes.AesGCM;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME:
                    KeyClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME:
                    KeyClass = ec.Ecdh;
                    break;
                default:
                    throw new Error(`ExportKey: Unsupported algorithm ${key.algorithm.name}`);
            }
            KeyClass.exportKey(format.toLocaleLowerCase(), key, function (err: Error, data: any) {
                if (err)
                    reject(err);
                else
                    if (Buffer.isBuffer(data)) {
                        let ubuf = new Uint8Array(<any>data);
                        resolve(ubuf.buffer);
                    }
                    else
                        resolve(data);
            });
        });
    }

    importKey(
        format: string,
        keyData: iwc.TBuffer,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): any {
        return new Promise(function (resolve: Function, reject: Function) {
            let _alg = prepare_algorithm(algorithm);
            let _data = prepare_data(keyData);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            if (format.toLocaleLowerCase() === "jwk") {
                if (Buffer.isBuffer(keyData)) {
                    throw new Error("ImportKey: keydData must be Object");
                }
                // copy input object
                let cpy: any = {};
                for (let i in _data) {
                    cpy[i] = _data[i];
                }
                _data = <any>cpy;
            }
            AlgClass.importKey(format.toLocaleLowerCase(), _data, _alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

}