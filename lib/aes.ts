import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as native from "./native_key";
import * as crypto from "crypto";

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Aes extends alg.AlgorithmBase {
    static generateKey(alg: IAesKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(alg);
        this.checkKeyGenParams(alg);

        let _key = native.SecretKey.generateAes(alg.length);

        return new AesKey(_key, alg, "secret");
    }

    static checkKeyGenParams(alg: IAesKeyGenParams) {
        if (!alg.length)
            throw new TypeError("AesKeyGenParams: length: Missing required property");
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new TypeError("AesKeyGenParams: length: Wrong value. Can be 128, 192, or 256");
        }
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    }

    static checkAlgorithmParams(alg: IAesAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
        if (!alg.tagLength)
            alg.tagLength = 128;
    }

    static wc2ssl(alg: IAesAlgorithmParams) {
        throw new Error("Not realized");
    }
}

export interface IAesKeyGenParams extends iwc.IAlgorithmIdentifier {
    length: number;
}

export interface IAesAlgorithmParams extends iwc.IAlgorithmIdentifier {
    iv: Buffer;
    additionalData?: Buffer;
    tagLength?: number;
}

export interface IAesCBCAlgorithmParams extends iwc.IAlgorithmIdentifier {
    iv: Buffer;
}

export class AesKey extends CryptoKey {
    length: number;

    constructor(key, alg: IAesKeyGenParams, type: string) {
        super(key, alg, type);
        this.length = alg.length;
        // TODO: get params from key if alg params is empty
    }
}

/*
export class AesGCM extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_GCM;

    static wc2ssl(alg: IAesAlgorithmParams) {
        let params = new graphene.AES.AesGCMParams(alg.iv, alg.additionalData, alg.tagLength);
        return { name: "AES_GCM", params: params };
    }

    static encrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let _alg = this.wc2pk11(alg);

        // TODO: Remove <any>
        let enc = session.createEncrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, enc.update(data)]);
        msg = Buffer.concat([msg, enc.final()]);
        return msg;
    }

    static decrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let _alg = this.wc2pk11(alg);

        // TODO: Remove <any>
        let dec = session.createDecrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, dec.update(data)]);
        msg = Buffer.concat([msg, dec.final()]);
        return msg;
    }

    static wrapKey(key: CryptoKey, wrappingKey: CryptoKey, alg: IAesAlgorithmParams): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkSecretKey(key);
        this.checkPublicKey(wrappingKey);
        let _alg = this.wc2pk11(alg);

        let wrappedKey: Buffer = session.wrapKey(wrappingKey.key, <any>_alg, key.key);
        return wrappedKey;
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAesAlgorithmParams, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(unwrapAlgorithm);
        this.checkAlgorithmHashedParams(unwrapAlgorithm);
        this.checkPrivateKey(unwrappingKey);
        let _alg = this.wc2pk11(unwrapAlgorithm);

        // TODO: convert unwrappedAlgorithm to PKCS11 Algorithm 

        let unwrappedKey: graphene.Key = session.unwrapKey(unwrappingKey.key, <any>_alg, { name: "" }, wrappedKey);
        // TODO: WrapKey with known AlgKey 
        return new CryptoKey(unwrappedKey, { name: "" });
    }
}
*/

export class AesCBC extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_CBC;

    static wc2ssl(alg: IAesAlgorithmParams) {
        return alg.iv;
    }

    static encrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let iv = this.wc2ssl(alg);
        let _alg = "aes-" + key.key.size + "-cbc";

        let enc = crypto.createCipheriv(_alg, key.key.handle, iv);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, enc.update(data)]);
        msg = Buffer.concat([msg, enc.final()]);
        return msg;
    }

    static decrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let iv = this.wc2ssl(alg);
        let _alg = "aes-" + key.key.size + "-cbc";


        let dec = crypto.createDecipheriv(_alg, key.key.handle, iv);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, dec.update(data)]);
        msg = Buffer.concat([msg, dec.final()]);
        return msg;
    }

    /*
    static wrapKey(key: CryptoKey, wrappingKey: CryptoKey, alg: IAesCBCAlgorithmParams): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkSecretKey(key);
        this.checkPublicKey(wrappingKey);
        let _alg = this.wc2pk11(alg);

        let wrappedKey: Buffer = session.wrapKey(wrappingKey.key, <any>_alg, key.key);
        return wrappedKey;
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAesCBCAlgorithmParams, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(unwrapAlgorithm);
        this.checkAlgorithmHashedParams(unwrapAlgorithm);
        this.checkPrivateKey(unwrappingKey);
        let _alg = this.wc2pk11(unwrapAlgorithm);

        // TODO: convert unwrappedAlgorithm to PKCS11 Algorithm 

        let unwrappedKey: graphene.Key = session.unwrapKey(unwrappingKey.key, <any>_alg, { name: "" }, wrappedKey);
        // TODO: WrapKey with known AlgKey 
        return new CryptoKey(unwrappedKey, { name: "" });
    }
    */

    static checkAlgorithmParams(alg: IAesCBCAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
    }
}