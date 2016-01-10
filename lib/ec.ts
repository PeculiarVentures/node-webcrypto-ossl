import * as Aes from "./aes";

import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as native from "./native_key";
import * as crypto from "crypto";

let base64url = require("base64url");

let ALG_NAME_ECDH = "ECDH";
let ALG_NAME_ECDSA = "ECDSA";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

function nc2ssl(nc) {
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
    return _namedCurve;
}

export class Ec extends alg.AlgorithmBase {
    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkKeyGenParams(alg);

        let _namedCurve = nc2ssl(alg.namedCurve);

        let _key = native.KeyPair.generateEc(_namedCurve);

        return {
            "privateKey": new EcKey(_key, alg, "private"),
            "publicKey": new EcKey(_key, alg, "public")
        };
    }

    static importKey(
        format: string,
        keyData: any,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): EcKey {
        this.checkAlgorithmIdentifier(algorithm);
        let pkey;
        if (format.toLowerCase() === "jwk") {
            // prepare data
            let key: any = {};
            key.crv = native.EcNamedCurves[nc2ssl(keyData.crv)];
            key.x = new Buffer(base64url.decode(keyData.x, "binary"), "binary");
            key.y = new Buffer(base64url.decode(keyData.y, "binary"), "binary");
            let keypair = new native.KeyPair();
            let key_type = "public";
            if (keyData.d) {
                key_type = "private";
                key.d = new Buffer(base64url.decode(keyData.d, "binary"), "binary");
            }
            keypair.importJwk("EC", key_type, key);
            pkey = new EcKey(keypair, <IEcKeyGenParams>algorithm, key_type);
            pkey.namedCurve = (<IEcKeyGenParams>algorithm).namedCurve;
        } else
            pkey = super.importKey(format, keyData, algorithm, extractable, keyUsages);
        return <EcKey>pkey;
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

export class EcKey extends CryptoKey {
    namedCurve: string;

    constructor(key, alg: IEcKeyGenParams, type: string) {
        super(key, alg, type);
        this.namedCurve = alg.namedCurve;
        // TODO: get params from key if alg params is empty
    }
}

export class Ecdsa extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDSA;

    static wc2ssl(alg) {
        this.checkAlgorithmHashedParams(alg);
        // let _alg = "ecdsa-with-" + alg.hash.name.toUpperCase().replace("-", "");
        let _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    }

    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        keyPair.privateKey.usages = ["sign"];
        keyPair.publicKey.usages = ["verify"];
        return keyPair;
    }

    static sign(alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer) {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2ssl(alg);

        let sig = native.sign(key.key, data, _alg);

        return sig;
    }

    static verify(alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2ssl(alg);

        let res = native.verify(key.key, data, signature, _alg);

        return res;
    }
}

export class Ecdh extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDH;

    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        keyPair.privateKey.usages = ["deriveKey"];
        keyPair.publicKey.usages = [];
        return keyPair;
    }

    static deriveKey(alg: IEcdsaAlgorithmParams, baseKey: CryptoKey, derivedKeyType: Aes.IAesKeyGenParams, extractable: boolean, keyUsages: string[]): CryptoKey {
        // check algorithm
        this.checkAlgorithmParams(alg);
        if (!alg.public)
            throw new TypeError("EcParams: public: Missing required property");
        this.checkPublicKey(alg.public);

        // check baseKey
        this.checkPrivateKey(baseKey);

        // check derivedKeyType
        if (typeof derivedKeyType !== "object")
            throw TypeError("derivedKeyType: AlgorithmIdentifier: Algorithm must be an Object");
        if (!(derivedKeyType.name && typeof (derivedKeyType.name) === "string"))
            throw TypeError("derivedKeyType: AlgorithmIdentifier: Missing required property name");
        let AesClass = null;
        let type = "secret";
        switch (derivedKeyType.name.toLowerCase()) {
            case Aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                Aes.AesCBC.checkKeyGenParams(<Aes.IAesKeyGenParams>derivedKeyType);
                AesClass = Aes.AesKey;
                break;
            default:
                throw new Error("derivedKeyType: Unknown Algorithm name in use");
        }

        // derive key
        let dKey: Buffer = native.deriveKey(baseKey.key, alg.public.key, derivedKeyType.length);

        return new AesClass(dKey, derivedKeyType, type);
    }
}
