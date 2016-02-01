import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import * as key from "./key";
import {CryptoKey} from "./key";
import * as native from "./native";
// import * as aes from "./aes";
let base64url = require("base64url");

let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
let ALG_NAME_RSA_OAEP = "RSA-OAEP";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export interface IJwkRsaPublicKey extends alg.IJwkKey {
    e: Buffer;
    n: Buffer;
}

export interface IJwkRsaPrivateKey extends IJwkRsaPublicKey {
    d: Buffer;
    p: Buffer;
    q: Buffer;
    dp: Buffer;
    dq: Buffer;
    qi: Buffer;
}

export class Rsa extends alg.AlgorithmBase {
    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void {
        try {
            let size = alg.modulusLength;
            let exp = new Buffer(alg.publicExponent);
            this.checkExponent(exp);
            // convert exp
            let nExp: number = 0;
            if (exp.toString("hex") === "010001")
                nExp = 1;
            native.Key.generateRsa(size, nExp, function(err, key) {
                try {
                    if (err) {
                        throw new Error(`Rsa: Can not generate new key\n${err.message}`);
                    }
                    else {
                        cb(null, {
                            privateKey: new RsaKey(key, alg, "private"),
                            publicKey: new RsaKey(key, alg, "public")
                        });
                    }
                }
                catch (e) {
                    cb(e, null);
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
        cb: (err: Error, d: iwc.ICryptoKey) => void
    ): void {
        try {
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    let jwk: IJwkRsaPrivateKey = <IJwkRsaPrivateKey>keyData;
                    this.checkAlgorithmIdentifier(algorithm);
                    this.checkAlgorithmHashedParams(algorithm);
                    // prepare data
                    jwk.n = new Buffer(base64url.decode(jwk.n, "binary"), "binary");
                    jwk.e = new Buffer(base64url.decode(jwk.e, "binary"), "binary");
                    let key_type = native.KeyType.PUBLIC;
                    if (jwk.d) {
                        key_type = native.KeyType.PRIVATE;
                        jwk.d = new Buffer(base64url.decode(jwk.d, "binary"), "binary");
                        jwk.p = new Buffer(base64url.decode(jwk.p, "binary"), "binary");
                        jwk.q = new Buffer(base64url.decode(jwk.q, "binary"), "binary");
                        jwk.dp = new Buffer(base64url.decode(jwk.dp, "binary"), "binary");
                        jwk.dq = new Buffer(base64url.decode(jwk.dq, "binary"), "binary");
                        jwk.qi = new Buffer(base64url.decode(jwk.qi, "binary"), "binary");
                    }
                    native.Key.importJwk(jwk, key_type, function(err, key) {
                        try {
                            if (err)
                                throw new Error(`ImportKey: Can not import key from JWK\n${err.message}`);
                            let rsa = new RsaKey(key, <IRsaKeyGenParams>algorithm, key_type ? "private" : "public");
                            rsa.modulusLength = jwk.n.length * 8;
                            rsa.publicExponent = new Uint8Array(jwk.e);
                            cb(null, rsa);
                        }
                        catch (e) {
                            cb(e, null);
                        }
                    });
                    break;
                case "spki":
                case "pkcs8":
                    if (!Buffer.isBuffer(keyData))
                        throw new Error("ImportKey: keyData is not a Buffer");
                    native.Key.importSpki(<Buffer>keyData, function(err, key) {
                        try {
                            if (err)
                                throw new Error(`ImportKey: Can not import key for ${format}\n${err.message}`);
                            let rsa = new RsaKey(key, <IRsaKeyGenParams>algorithm, format.toLocaleLowerCase() === "spki" ? "public" : "private");
                            rsa.modulusLength = jwk.n.length * 8;
                            rsa.publicExponent = new Uint8Array(jwk.e);
                            cb(null, rsa);
                        }
                        catch (e) {
                            cb(err, null);
                        }
                    });
                    break;
                default:
                    throw new Error(`ImportKey: Wrong format value '${format}'`);
            }
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            let nkey = <native.Key>key.native;
            let type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nkey.exportJwk(type, function(err, data) {
                        try {
                            let jwk = <IJwkRsaPrivateKey>data;

                            // convert base64 -> base64url for all props
                            jwk.e = base64url(jwk.e);
                            jwk.n = base64url(jwk.n);
                            if (key.type === "private") {
                                jwk.d = base64url(jwk.d);
                                jwk.p = base64url(jwk.p);
                                jwk.q = base64url(jwk.q);
                                jwk.dp = base64url(jwk.dp);
                                jwk.dq = base64url(jwk.dq);
                                jwk.qi = base64url(jwk.qi);
                            }
                            cb(null, jwk);
                        }
                        catch (e) {
                            cb(e, null);
                        }
                    });
                    break;
                case "spki":
                    this.checkPublicKey(key);
                    nkey.exportSpki(cb);
                    break;
                case "pkcs8":
                    this.checkPrivateKey(key);
                    nkey.exportPkcs8(cb);
                    break;
                default:
                    throw new Error(`ExportKey: Unknown export frmat '${format}'`);
            }
        }
        catch (e) {
            cb(e, null);
        }
    }

    static checkExponent(exp: Buffer) {
        let e = exp.toString("hex");
        if (!(e === "03" || e === "010001"))
            throw new TypeError("RsaKeyGenParams: Wrong publicExponent value");
    }

    static checkRsaGenParams(alg: IRsaKeyGenParams) {
        if (!alg.modulusLength)
            throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
        if (alg.modulusLength < 256 || alg.modulusLength > 16384)
            throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
        if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
            throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    }

    static wc2ssl(alg) {
        RsaPKCS1.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    }
}

export interface IRsaKeyGenParams extends iwc.IAlgorithmIdentifier {
    modulusLength: number;
    publicExponent: Uint8Array;
}

export interface IRsaOaepEncryptParams extends iwc.IAlgorithmIdentifier {
    label?: Uint8Array;
}

export class RsaKey extends CryptoKey {
    modulusLength: number;
    publicExponent: Uint8Array;

    constructor(key, alg: IRsaKeyGenParams, type: string) {
        super(key, alg, type);
        this.modulusLength = alg.modulusLength;
        this.publicExponent = alg.publicExponent;
        // TODO: get params from key if alg params is empty
    }
}

export class RsaPKCS1 extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PKCS1;

    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkRsaGenParams(alg);
            this.checkAlgorithmHashedParams(alg);

            super.generateKey(alg, extractable, keyUsages, function(err: Error, key: iwc.ICryptoKey) {
                try {
                    if (err) {
                        cb(err, null);
                    }
                    else {
                        if (key.type === "public") {
                            key.usages = ["verify"];
                        }
                        else {
                            key.usages = ["sign"];
                        }
                        cb(null, key);
                    }
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            super.exportKey(format, key, function(err, data) {
                try {
                    if (format === "jwk") {
                        let jwk = <IJwkRsaPrivateKey>data;
                        // set alg
                        let reg = /(\d+)$/;
                        jwk.alg = "RS" + reg.exec(key.algorithm.hash.name)[1];
                        jwk.ext = true;
                        if (key.type === "public") {
                            jwk.key_ops = ["verify"];
                        }
                        else {
                            jwk.key_ops = ["sign"];
                        }
                        cb(null, jwk);
                    }
                    else
                        cb(null, data);
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPrivateKey(key);
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = <native.Key>key.native;

            nkey.sign(_alg, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPublicKey(key);
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = <native.Key>key.native;

            nkey.verify(_alg, data, signature, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

}

export class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;
}

export class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkRsaGenParams(alg);
            this.checkAlgorithmHashedParams(alg);

            super.generateKey(alg, extractable, keyUsages, function(err: Error, key: iwc.ICryptoKey) {
                try {
                    if (err) {
                        cb(err, null);
                    }
                    else {
                        if (key.type === "public") {
                            key.usages = ["encrypt", "wrapKey"];
                        }
                        else {
                            key.usages = ["decrypt", "unwrapKey"];
                        }
                        cb(null, key);
                    }
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void {
        try {
            super.exportKey(format, key, function(err, data) {
                try {
                    if (format === "jwk") {
                        let jwk = <IJwkRsaPrivateKey>data;
                        // set alg
                        let md_size = /(\d+)$/.exec(key.algorithm.hash.name)[1];
                        jwk.alg = "RSA-OAEP";
                        if (md_size !== "1") {
                            jwk.alg += "-" + md_size;
                        }
                        jwk.ext = true;
                        if (key.type === "public") {
                            jwk.key_ops = ["encrypt", "wrapKey"];
                        }
                        else {
                            jwk.key_ops = ["decrypt", "unwrapKey"];
                        }
                        cb(null, jwk);
                    }
                    else
                        cb(null, data);
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static encrypt(alg: IRsaOaepEncryptParams, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPublicKey(key);
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = <native.Key>key.native;

            let label = null;
            if (alg.label) {
                label = new Buffer(alg.label);
            }

            nkey.RsaOaepEncDec(_alg, data, label, false, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static decrypt(alg: IRsaOaepEncryptParams, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPrivateKey(key);
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = <native.Key>key.native;

            let label = null;
            if (alg.label) {
                label = new Buffer(alg.label);
            }

            nkey.RsaOaepEncDec(_alg, data, label, true, cb);
        }
        catch (e) {
            cb(e, null);
        }
    }

    static wrapKey(key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkSecretKey(key);
            this.checkPublicKey(wrappingKey);
            let _alg = this.wc2ssl(alg);
            let nkey = <native.Key>wrappingKey.native;
            let nAesKey = <native.AesKey>key.native;

            nAesKey.export(function(err, data) {
                if (err) {
                    cb(err, null);
                }
                else {
                    nkey.RsaOaepEncDec(_alg, data, null, false, cb);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void {
        try {
            this.checkAlgorithmIdentifier(unwrapAlgorithm);
            this.checkAlgorithmHashedParams(unwrapAlgorithm);
            this.checkPrivateKey(unwrappingKey);

            let _alg = this.wc2ssl(unwrapAlgorithm);
            let nkey = <native.Key>unwrappingKey.native;

            // convert unwrappedAlgorithm to PKCS11 Algorithm
            let AlgClass = null;
            cb(new Error("Not implemented"), null);
            // switch (unwrappedAlgorithm.name) {
            // case aes.ALG_NAME_AES_CTR:
            // case aes.ALG_NAME_AES_CMAC:
            // case aes.ALG_NAME_AES_CFB:
            // case aes.ALG_NAME_AES_KW:
            // case aes.ALG_NAME_AES_CBC:
            // aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
            // AlgClass = aes.AesCBC;
            // break;
            /*
            case aes.ALG_NAME_AES_GCM:
                aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
                AlgClass = aes.AesGCM;
                break;
            */
            // default:
            // throw new Error("Unsupported algorithm in use");

            // }

            // let unwrappedKey: Buffer = unwrappingKey.key.decryptRsaOAEP(wrappedKey, _alg);
            // return new AlgClass(unwrappedKey, unwrappedAlgorithm);
        }
        catch (e) {
            cb(e, null);
        }
    }
}