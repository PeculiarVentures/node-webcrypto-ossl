import * as aes from "./aes";

import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import * as key from "./key";
import {CryptoKey} from "./key";
import * as native from "./native";
import * as crypto from "crypto";

let base64url = require("base64url");

let ALG_NAME_ECDH = "ECDH";
let ALG_NAME_ECDSA = "ECDSA";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export interface IJwkEcPublicKey extends alg.IJwkKey {
    x: Buffer;
    y: Buffer;
    crv: string;
}

export interface IJwkEcPrivateKey extends IJwkEcPublicKey {
    d: Buffer;
}

function nc2ssl(nc: any) {
    let _namedCurve = "";
    switch (nc.toUpperCase()) {
        case "P-192":
            _namedCurve = "secp192r1";
            break;
        case "P-256":
            _namedCurve = "secp256r1";
            break;
        case "P-384":
            _namedCurve = "secp384r1";
            break;
        case "P-521":
            _namedCurve = "secp521r1";
            break;
        default:
            throw new Error("Unsupported namedCurve in use");
    }
    return (native.EcNamedCurves as any)[_namedCurve];
}

export class Ec extends alg.AlgorithmBase {

    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: any, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenParams(alg);

            let namedCurve = nc2ssl(alg.namedCurve);

            native.Key.generateEc(namedCurve, function (err, key) {
                cb(null, {
                    "privateKey": new CryptoKey(key, alg, "private", extractable, keyUsages),
                    "publicKey": new CryptoKey(key, alg, "public", extractable, keyUsages)
                });
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void {
        try {
            this.checkKeyType(format);
            this.checkAlgorithmIdentifier(algorithm);

            switch (format) {
                case "pkcs8":
                    native.Key.importPkcs8(<Buffer>keyData, function (err, key) {
                        if (!err) {
                            let ec = new CryptoKey(key, algorithm, "private", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                case "spki":
                    native.Key.importSpki(<Buffer>keyData, function (err, key) {
                        if (!err) {
                            let ec = new CryptoKey(key, algorithm, "public", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                case "jwk":
                    // prepare data
                    let jwk: IJwkEcPublicKey = {
                        kty: "EC",
                        key_ops: [],
                        crv: "",
                        x: null,
                        y: null
                    };
                    let inJwk = <IJwkEcPrivateKey>keyData;
                    jwk.crv = nc2ssl(inJwk.crv);
                    jwk.x = new Buffer(base64url.decode(inJwk.x, "binary"), "binary");
                    jwk.y = new Buffer(base64url.decode(inJwk.y, "binary"), "binary");
                    let key_type = native.KeyType.PUBLIC;
                    if (inJwk.d) {
                        key_type = native.KeyType.PRIVATE;
                        (<IJwkEcPrivateKey>jwk).d = new Buffer(base64url.decode(inJwk.d, "binary"), "binary");
                    }
                    native.Key.importJwk(jwk, key_type, function (err, key) {
                        if (!err) {
                            let ec = new CryptoKey(key, algorithm, key_type === native.KeyType.PRIVATE ? "private" : "public", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                default:
                    throw new Error("Ec::ImportKey: Wrong import key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: iwc.ICryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            this.checkKeyType(format);

            let nkey = <native.Key>key.native;
            switch (format) {
                case "spki":
                    nkey.exportSpki(cb);
                    break;
                case "pkcs8":
                    nkey.exportPkcs8(cb);
                    break;
                case "jwk":
                    // create jwk  
                    let pubJwk: IJwkEcPublicKey = {
                        kty: "EC",
                        crv: (<IEcKeyGenParams>key.algorithm).namedCurve,
                        key_ops: [],
                        x: null,
                        y: null,
                        ext: true
                    };
                    let key_type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
                    nkey.exportJwk(key_type, function (err, jwk) {
                        if (!err) {
                            try {
                                pubJwk.x = base64url(jwk.x);
                                pubJwk.y = base64url(jwk.y);
                                if (key_type === native.KeyType.PRIVATE)
                                    (<IJwkEcPrivateKey>pubJwk).d = base64url(jwk.d);
                                cb(null, pubJwk);
                            }
                            catch (e) {
                                cb(e, null);
                            }
                        }
                        else
                            cb(err, null);
                    });
                    break;
                default:
                    throw new Error("Ec::ExportKey: Wrong export key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    }

    static checkKeyGenParams(alg: IEcKeyGenParams) {
        this.checkAlgorithmParams(alg);
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknown hash algorithm in use");
    }

    static checkAlgorithmParams(alg: IEcAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.namedCurve)
            throw new TypeError("EcParams: namedCurve: Missing required property");
        switch (alg.namedCurve.toUpperCase()) {
            case "P-192":
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new TypeError("EcParams: namedCurve: Wrong value. Can be P-192, P-256, P-384, or P-521");
        }
        alg.namedCurve = alg.namedCurve.toUpperCase();
    }

    static wc2ssl(alg: IEcAlgorithmParams) {
        throw new Error("Not realized");
    }
}

export interface IEcKeyGenParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
}

export interface IEcAlgorithmParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
    public?: CryptoKey;
}

export interface IEcdsaAlgorithmParams extends IEcAlgorithmParams {
    hash: {
        name: string;
    };
}

export class Ecdsa extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDSA;

    static wc2ssl(alg: any) {
        this.checkAlgorithmHashedParams(alg);
        // let _alg = "ecdsa-with-" + alg.hash.name.toUpperCase().replace("-", "");
        let _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    }

    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: any, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void {
        super.generateKey(alg, extractable, keyUsages, function (err, keys) {
            if (!err) {
                keys.privateKey.usages = ["sign"];
                keys.publicKey.usages = ["verify"];
                cb(null, keys);
            }
            else
                cb(err, null);
        });
    }

    static sign(alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static sign(alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static sign(alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkPrivateKey(key);
            let _alg = this.wc2ssl(alg);

            (<native.Key>key.native).sign(_alg, data, cb);

        }
        catch (e) {
            cb(e, null);
        }
    }

    static verify(alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    static verify(alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    static verify(alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkPublicKey(key);
            let _alg = this.wc2ssl(alg);

            (<native.Key>key.native).verify(_alg, data, signature, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        super.exportKey(format, key, function (err, d) {
            if (!err) {
                if (format === "jwk") {
                    let jwk = <IJwkEcPrivateKey>d;
                    if (key.type === "public")
                        jwk.key_ops = ["verify"];
                    else
                        jwk.key_ops = ["sign"];
                    cb(null, jwk);
                }
                else
                    cb(null, d);
            }
            else
                cb(err, null);
        });
    }
}

export interface IEcDhAlgorithmParams extends IEcAlgorithmParams {
}

export class Ecdh extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDH;

    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void {
        super.generateKey(alg, extractable, keyUsages, function (err, keys) {
            if (!err) {
                keys.privateKey.usages = ["deriveKey"];
                keys.publicKey.usages = [];
                cb(null, keys);
            }
            else
                cb(err, null);
        });
    }

    static deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static deriveKey(algorithm: IEcDhAlgorithmParams, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static deriveKey(algorithm: IEcDhAlgorithmParams, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            this.checkAlgorithmParams(algorithm);
            this.checkPublicKey(algorithm.public);
            this.checkPrivateKey(baseKey);
            if (algorithm.public.algorithm.name !== "ECDH")
                throw new TypeError("ECDH::CheckAlgorithm: Public key is not ECDH");

            let type = "secret";
            switch (derivedKeyType.name.toLowerCase()) {
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    aes.AesCBC.checkKeyGenParams(<aes.IAesKeyGenParams>derivedKeyType);
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    aes.AesGCM.checkKeyGenParams(<aes.IAesKeyGenParams>derivedKeyType);
                    break;
                default:
                    throw new Error("derivedKeyType: Unknown Algorithm name in use");
            }

            // derive key
            (<native.Key>baseKey.native).EcdhDeriveKey(algorithm.public.native, (<aes.IAesKeyGenParams>derivedKeyType).length, function (err, raw) {
                if (!err) {
                    native.AesKey.import(raw, function (err, key) {
                        if (!err) {
                            let aesKey = new CryptoKey(key, derivedKeyType, "secret", extractable, keyUsages);
                            cb(null, aesKey);
                        }
                        else
                            cb(err, null);
                    });
                }
                else
                    cb(err, null);
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static deriveBits(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void;
    static deriveBits(algorithm: IEcDhAlgorithmParams, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void;
    static deriveBits(algorithm: IEcDhAlgorithmParams, baseKey: CryptoKey, length: number, cb: (err: Error, dbits: Buffer) => void): void {
        try {
            this.checkAlgorithmParams(algorithm);
            this.checkPublicKey(algorithm.public);
            this.checkPrivateKey(baseKey);
            if (algorithm.public.algorithm.name !== "ECDH")
                throw new TypeError("ECDH::CheckAlgorithm: Public key is not ECDH");

            if (!length)
                throw new TypeError("ECDH::DeriveBits: Wrong 'length' value");

            // derive bits
            (<native.Key>baseKey.native).EcdhDeriveBits(algorithm.public.native, length, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        super.exportKey(format, key, function (err, d) {
            if (!err) {
                if (format === "jwk") {
                    let jwk = <IJwkEcPrivateKey>d;
                    if (key.type === "public")
                        jwk.key_ops = [];
                    else
                        jwk.key_ops = ["deriveKey"];
                    cb(null, jwk);
                }
                else
                    cb(null, d);
            }
            else
                cb(err, null);
        });
    }

    static checkAlgorithmParams(alg: IEcDhAlgorithmParams) {
        super.checkAlgorithmParams(alg);
    }
}
