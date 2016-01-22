/// <reference path="./promise.ts" />

import {CryptoKey} from "./key";

import * as alg from "./alg";
import * as rsa from "./rsa";
import * as aes from "./aes";
import * as ec from "./ec";

import * as iwc from "./iwebcrypto";

function prepare_algorithm(alg: iwc.AlgorithmType): iwc.IAlgorithmIdentifier {
    let _alg: iwc.IAlgorithmIdentifier = { name: "" };
    if (alg instanceof String) {
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
    return (data instanceof ArrayBuffer) ? ab2b(data) : data;
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

export class SubtleCrypto implements iwc.ISubtleCrypto {

    generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): Promise {
        let that = this;
        return new Promise(function(resolve, reject) {
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
            let key = AlgClass.generateKey(_alg, extractable, keyUsages, function(e, k) {
                if (e)
                    reject(e);
                else
                    resolve(k);
            });
        });
    }

    sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function(resolve, reject) {
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
            let signature = AlgClass.sign(_alg, key, _data);
            resolve(new Uint8Array(signature).buffer);
        });
    }

    verify(algorithm: iwc.AlgorithmType, key: CryptoKey, signature: iwc.TBuffer, data: iwc.TBuffer): Promise {
        let that = this;
        let _signature = prepare_data(signature);
        let _data = prepare_data(data);

        return new Promise(function(resolve, reject) {
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
            let valid = AlgClass.verify(_alg, key, _signature, _data);
            resolve(valid);
        });
    }

    encrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function(resolve, reject) {
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
            let msg = AlgClass.encrypt(_alg, key, _data);
            resolve(new Uint8Array(msg).buffer);
        });
    }

    decrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise {
        let that = this;
        let _data = prepare_data(data);

        return new Promise(function(resolve, reject) {
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
            let msg = AlgClass.decrypt(_alg, key, _data);
            resolve(new Uint8Array(msg).buffer);
        });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: iwc.IAlgorithmIdentifier): Promise {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                /*
            case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                AlgClass = aes.AesGCM;
                break;
                */
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            let wrappedKey = AlgClass.wrapKey(key, wrappingKey, _alg);
            resolve(new Uint8Array(wrappedKey).buffer);
        });
    }

    unwrapKey(format: string, wrappedKey: iwc.TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise {
        let that = this;
        let _wrappedKey = prepare_data(wrappedKey);

        return new Promise(function(resolve, reject) {
            let _alg1 = prepare_algorithm(unwrapAlgorithm);
            let _alg2 = prepare_algorithm(unwrappedAlgorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg1.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                /*
            case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                AlgClass = aes.AesGCM;
                break;
                */
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            let unwrappedKey = AlgClass.unwrapKey(_wrappedKey, unwrappingKey, _alg1, _alg2, extractable, keyUsages);
            resolve(unwrappedKey);
        });
    }

    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise {
        let that = this;

        return new Promise(function(resolve, reject) {
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
            let key: CryptoKey = AlgClass.deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages);
            resolve(key);
        });
    }

    exportKey(format: string, key: CryptoKey): Promise {
        let that = this;

        return new Promise(function(resolve, reject) {
            let data = alg.AlgorithmBase.exportKey(format, key);
            if (Buffer.isBuffer(data)) {
                let ubuf = new Uint8Array(<any>data);
                resolve(ubuf.buffer);
            }
            else
                resolve(data);
        });
    }

    importKey(
        format: string,
        keyData: iwc.TBuffer,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): Promise {
        return new Promise(function(resolve, reject) {
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
            let key = AlgClass.importKey(format, _data, _alg, extractable, keyUsages);
            resolve(key);
        });
    }

}