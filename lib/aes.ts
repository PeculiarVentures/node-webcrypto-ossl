import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as native from "./native";
import * as crypto from "crypto";

let base64url = require("base64url");

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export interface IJwkAesKey extends alg.IJwkKey {
    k: Buffer;
}

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
    static generateKey(alg: IAesKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenParams(alg);

            native.AesKey.generate(alg.length / 8, function(err, key) {
                if (!err) {
                    cb(null, new AesKey(key, alg, "secret"));
                }
                else {
                    cb(err, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static importKey(
        format: string,
        keyData: Buffer | alg.IJwkKey,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[],
        cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            this.checkAlgorithmIdentifier(algorithm);
            let raw: Buffer;
            if (format === "jwk") {
                let jwk: IJwkAesKey = <IJwkAesKey>keyData;
                // prepare data
                if (!jwk.k) {
                    throw new Error("Aes::ImportKey: Wrong JWK data");
                }
                raw = new Buffer(base64url.decode(jwk.k, "binary"), "binary");
            } else if (format === "raw") {
                raw = <Buffer>keyData;
            }
            else {
                throw new Error("Aes::ImportKeyWrong: Wrong iport key format");
            }
            let alg: IAesKeyGenParams = <IAesKeyGenParams>algorithm;
            alg.length = raw.length * 8;

            let aes = native.AesKey.import(raw, function(err, key) {
                if (!err) {
                    let aes = new AesKey(key, alg, "secret");
                    cb(null, aes);
                }
                else
                    cb(err, null);
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            let aes = <AesKey>key;
            let nkey = <native.AesKey>key.native;
            switch (format) {
                case "jwk":
                    let jwk: IJwkAesKey = {
                        kty: "oct",
                        alg: null,
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: null,
                        ext: true
                    };
                    // set alg
                    jwk.alg = "A" + aes.algorithm.length + /-(\w+)$/.exec(aes.algorithm.name)[1];
                    nkey.export(function(err, data) {
                        if (!err) {
                            jwk.k = base64url(data);
                            cb(null, jwk);
                        }
                        else {
                            cb(err, null);
                        }
                    });
                    break;
                case "raw":
                    nkey.export(cb);
                    break;
                default:
                    throw new Error("Aes::ExportKey: Wrong export key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    }

    static checkKeyGenParams(alg: iwc.IAlgorithmIdentifier)
    static checkKeyGenParams(alg: IAesKeyGenParams);
    static checkKeyGenParams(alg: any) {
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

    algorithm: IAesKeyGenParams;

    constructor(key: native.AesKey, alg: IAesKeyGenParams, type: string) {
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

    static encrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(key.algorithm);
            this.checkKeyGenParams(key.algorithm);
            let _alg = this.wc2ssl(key.algorithm);
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);

            let nkey = <native.AesKey>key.native;
            throw new Error("Not implemented");
        }
        catch (e) {
            cb(e, null);
        }
    }

    static decrypt(alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(key.algorithm);
            this.checkKeyGenParams(key.algorithm);
            let _alg = this.wc2ssl(key.algorithm);
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);

            let nkey = <native.AesKey>key.native;
            throw new Error("Not implemented");
        }
        catch (e) {
            cb(e, null);
        }
    }

}

export class AesCBC extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_CBC;

    static wc2ssl(alg: IAesAlgorithmParams) {
        return alg.iv;
    }

    static encrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);
            let iv = this.wc2ssl(alg);
            let aes = <AesKey>key;
            let nkey = <native.AesKey>key.native;
            let _alg = "CBC";

            nkey.encrypt(_alg, iv, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static decrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);
            let iv = this.wc2ssl(alg);
            let aes = <AesKey>key;
            let nkey = <native.AesKey>key.native;
            let _alg = "CBC";

            nkey.decrypt(_alg, iv, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static checkAlgorithmParams(alg: IAesCBCAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
    }
}