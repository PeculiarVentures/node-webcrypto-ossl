import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as native from "./native_key";
import * as crypto from "crypto";

let base64url = require("base64url");

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

/**
 * Prepare array of data before it's using 
 * @param data Array which must be prepared
 */
function prepare_data(data: Buffer | ArrayBuffer) {
    return (!Buffer.isBuffer(data)) ? ab2b(data) : data;
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(ab: ArrayBuffer) {
    let buf = new Uint8Array(ab);
    return new Buffer(buf);
}

export class Aes extends alg.AlgorithmBase {
    static generateKey(alg: IAesKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(alg);
        this.checkKeyGenParams(alg);

        let _key = native.SecretKey.generateAes(alg.length);

        return new AesKey(_key, alg, "secret");
    }

    static importKey(
        format: string,
        keyData: any,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): AesKey {
        this.checkAlgorithmIdentifier(algorithm);
        let pkey;
        if (format.toLowerCase() === "jwk") {
            // prepare data
            let key: any = {};
            key.k = new Buffer(base64url.decode(keyData.k, "binary"), "binary");
            let AesClass = null;
            let alg: IAesKeyGenParams = <IAesKeyGenParams>algorithm;
            alg.length = +/(\d+)/.exec(keyData.alg)[1];
            pkey = new AesKey(new native.SecretKey(key.k), alg, "secret");
        } else
            pkey = super.importKey(format, keyData, algorithm, extractable, keyUsages);
        return <AesKey>pkey;
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
        // this.length = alg.length;
        // TODO: get params from key if alg params is empty
        this.usages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
    }
}

export class AesGCM extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_GCM;

    static wc2ssl(alg: any) {
        let ret = "";
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                ret = `aes-${alg.length}-gcm`;
                break;
            default:
                throw new Error(`Unknown AES key length in use '${alg.length}'`);
        }
        return ret;
    }

    static encrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(key.algorithm);
        this.checkKeyGenParams(key.algorithm);
        let _alg = this.wc2ssl(key.algorithm);
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);

        let cipher: any = crypto.createCipheriv(_alg, key.key.handle, alg.iv);
        cipher.setAAD(prepare_data(alg.additionalData));

        let enc = cipher.update(data).toString("binary");
        enc += cipher.final("binary");

        let tag = cipher.getAuthTag().toString("binary");

        let msg = enc + tag;

        return new Buffer(msg, "binary");
    }

    static decrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(key.algorithm);
        this.checkKeyGenParams(key.algorithm);
        let _alg = this.wc2ssl(key.algorithm);
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);

        let strData = data.toString("binary");
        let _data = strData.substr(0, (strData.length - (alg.tagLength / 8)));
        let tag = strData.substr(strData.length - (alg.tagLength / 8));

        let decipher: any = crypto.createDecipheriv(_alg, key.key.handle, alg.iv);
        decipher.setAAD(prepare_data(alg.additionalData));
        decipher.setAuthTag(new Buffer(tag, "binary"));

        let dec = decipher.update(_data, "binary", "binary");
        dec += decipher.final("binary");

        return new Buffer(dec, "binary");
    }

    static wrapKey(key: CryptoKey, wrappingKey: CryptoKey, alg: IAesAlgorithmParams): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkPublicKey(wrappingKey);
        return this.encrypt(alg, key, new Buffer("No data"));
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAesAlgorithmParams, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        throw new Error("Unsupported yet");
    }
}

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

    static checkAlgorithmParams(alg: IAesCBCAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
    }
}