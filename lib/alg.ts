import * as iwc from "./iwebcrypto";
import * as key from "./key";
import * as native from "./native";

export interface IJwkKey extends JWK {
    kty: string;
    ext?: boolean;
    key_ops: string[];
}

export interface IAlgorithmBase {
    generateKey(alg: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey | CryptoKeyPair) => void): void;
    sign(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    verify(alg: NodeAlgorithm, key: key.OsslCryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    encrypt(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    decrypt(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    wrapKey(key: key.OsslCryptoKey, wrappingKey: key.OsslCryptoKey, alg: NodeAlgorithm, cb: (err: Error, d: Buffer) => void): void;
    unwrapKey(wrappedKey: Buffer, unwrappingKey: key.OsslCryptoKey, unwrapAlgorithm: NodeAlgorithm, unwrappedAlgorithm: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void;
    deriveKey(algorithm: NodeAlgorithm, baseKey: key.OsslCryptoKey, derivedKeyType: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void;
    deriveBits(algorithm: NodeAlgorithm, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void;
    exportKey(format: string, key: key.OsslCryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    importKey(format: string, keyData: Buffer | IJwkKey, algorithm: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void;
}

export class AlgorithmBase {
    static ALGORITHM_NAME: string = "";

    static generateKey(alg: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey | CryptoKeyPair) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static sign(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static verify(alg: NodeAlgorithm, key: key.OsslCryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static encrypt(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static decrypt(alg: NodeAlgorithm, key: key.OsslCryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static wrapKey(key: key.OsslCryptoKey, wrappingKey: key.OsslCryptoKey, alg: NodeAlgorithm, cb: (err: Error, d: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: key.OsslCryptoKey, unwrapAlgorithm: NodeAlgorithm, unwrappedAlgorithm: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static deriveKey(algorithm: NodeAlgorithm, baseKey: key.OsslCryptoKey, derivedKeyType: NodeAlgorithm, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static deriveBits(algorithm: NodeAlgorithm, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: key.OsslCryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            throw new Error("Method is not supported");
        } catch (e) {
            cb(e, null);
        }
    }

    static importKey(
        format: string,
        keyData: Buffer | IJwkKey,
        algorithm: NodeAlgorithm,
        extractable: boolean,
        keyUsages: string[],
        cb: (err: Error, d: CryptoKey) => void): void {
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

    static checkKey(key: CryptoKey, type: string) {
        if (!key)
            throw new TypeError("CryptoKey: Key can not be null");
        if (key.type !== type)
            throw new TypeError(`CryptoKey: Wrong key type in use. Must be '${type}'`);
    }

    static checkPrivateKey(key: CryptoKey) {
        this.checkKey(key, "private");
    }

    static checkPublicKey(key: CryptoKey) {
        this.checkKey(key, "public");
    }

    static checkSecretKey(key: CryptoKey) {
        this.checkKey(key, "secret");
    }
} 