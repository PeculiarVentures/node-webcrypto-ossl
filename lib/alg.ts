import * as iwc from "./iwebcrypto";
import * as key from "./key";
import * as native from "./native";
let base64url = require("base64url");

export interface IJwkKey {
    kty: string;
    ext?: boolean;
    key_ops: string[];
}

export interface IAlgorithmBase {
    generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    encrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    decrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    wrapKey(key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void;
    unwrapKey(wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    deriveBits(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void;
    exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    importKey(format: string, keyData: Buffer | IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
}

export class AlgorithmBase {
    static ALGORITHM_NAME: string = "";

    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static encrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static decrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static wrapKey(key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static deriveBits(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static importKey(
        format: string,
        keyData: Buffer | IJwkKey,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[],
        cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    }

    /**
     * check type of exported data
     * @param {string} type type of exported data (raw, jwk, spki, pkcs8)
     */
    static checkKeyType(type: string) {
        const ERROR_TYPE = "KeyType";
        let _type = type.toLowerCase();
        switch (type) {
            case "spki":
            case "pkcs8":
            case "jwk":
            case "raw":
                break;
            default:
                throw new TypeError(`${ERROR_TYPE}: Unknown key type in use '${_type}'`);
        }
    }

    static checkExportKey(format: string, key: CryptoKey) {
        const ERROR_TYPE = "ExportKey";

        let _format = format.toLowerCase();
        this.checkKeyType(format);

        if (key.type === "private") {
            if (_format !== "pkcs8")
                throw new TypeError(`${ERROR_TYPE}: Only 'pkcs8' is allowed`);
        }
        else if (key.type === "public") {
            if (_format !== "spki")
                throw new TypeError(`${ERROR_TYPE}: Only 'spki' is allowed`);
        }
        else {
            throw new TypeError(`${ERROR_TYPE}: Only for 'private' and 'public' key allowed`);
        }
    }

    static checkAlgorithmIdentifier(alg: any) {
        if (typeof alg !== "object")
            throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
        if (!(alg.name && typeof (alg.name) === "string"))
            throw TypeError("AlgorithmIdentifier: Missing required property name");
        if (alg.name.toLowerCase() !== this.ALGORITHM_NAME.toLowerCase())
            throw new Error("AlgorithmIdentifier: Wrong algorithm name. Must be " + this.ALGORITHM_NAME);
        alg.name = this.ALGORITHM_NAME;
    }

    static checkAlgorithmHashedParams(alg: any) {
        if (!alg.hash)
            throw new TypeError("AlgorithmHashedParams: Missing required property hash");
        if (typeof alg.hash !== "object")
            throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
        if (!(alg.hash.name && typeof (alg.hash.name) === "string"))
            throw TypeError("AlgorithmIdentifier: Missing required property name");
    }

    static checkKey(key: iwc.ICryptoKey, type: string) {
        if (!key)
            throw new TypeError("CryptoKey: Key can not be null");
        if (key.type !== type)
            throw new TypeError(`CryptoKey: Wrong key type in use. Must be '${type}'`);
    }

    static checkPrivateKey(key: iwc.ICryptoKey) {
        this.checkKey(key, "private");
    }

    static checkPublicKey(key: iwc.ICryptoKey) {
        this.checkKey(key, "public");
    }

    static checkSecretKey(key: iwc.ICryptoKey) {
        this.checkKey(key, "secret");
    }
} 