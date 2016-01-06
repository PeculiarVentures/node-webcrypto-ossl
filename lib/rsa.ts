import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as native from "./native_key";
import * as aes from "./aes";

let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
let ALG_NAME_RSA_OAEP = "RSA-OAEP";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Rsa extends alg.AlgorithmBase {
    static generateKey(alg: any, extractable: boolean, keyUsages: string[]): iwc.ICryptoKeyPair {
        let size = alg.modulusLength;
        let exp = new Buffer(alg.publicExponent);
        this.checkExponent(exp);
        // convert exp
        let nExp: number = 0;
        if (exp.toString("hex") === "010001")
            nExp = 1;
        let _key = native.KeyPair.generateRsa(size, nExp);

        return {
            privateKey: new RsaKey(_key, alg, "private"),
            publicKey: new RsaKey(_key, alg, "public")
        };
    }

    static importKey(
        format: string,
        keyData: Buffer,
        algorithm: iwc.IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): RsaKey {
        this.checkAlgorithmIdentifier(algorithm);
        this.checkAlgorithmHashedParams(algorithm);
        let pkey = super.importKey(format, keyData, algorithm, extractable, keyUsages);
        return <RsaKey>pkey;
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

    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[]): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkRsaGenParams(alg);
        this.checkAlgorithmHashedParams(alg);

        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        keyPair.privateKey.usages = ["sign"];
        keyPair.publicKey.usages = ["verify"];
        return keyPair;
    }

    static sign(alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer) {
        this.checkAlgorithmIdentifier(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2ssl(key.algorithm);

        let sig = native.sign(key.key, data, _alg);

        return sig;
    }

    static verify(alg: iwc.IAlgorithmIdentifier, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
        this.checkAlgorithmIdentifier(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2ssl(key.algorithm);

        let res = native.verify(key.key, data, signature, _alg);

        return res;
    }

}

export class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;

    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[]): iwc.ICryptoKeyPair {
        throw new Error("not realized in this implementation");
    }
}

export class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[]): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkRsaGenParams(alg);
        this.checkAlgorithmHashedParams(alg);

        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        keyPair.privateKey.usages = ["decrypt", "unwrapKey"];
        keyPair.publicKey.usages = ["encrypt", "wrapKey"];
        return keyPair;
    }

    static encrypt(alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2ssl(key.algorithm);

        let msg = key.key.encryptRsaOAEP(data, _alg);

        return msg;
    }

    static decrypt(alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2ssl(key.algorithm);

        let msg = key.key.decryptRsaOAEP(data, _alg);

        return msg;
    }
    static wrapKey(key: CryptoKey, wrappingKey: CryptoKey, alg: iwc.IAlgorithmIdentifier): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkSecretKey(key);
        this.checkPublicKey(wrappingKey);
        let _alg = this.wc2ssl(alg);

        let wrappedKey: Buffer = wrappingKey.key.encryptRsaOAEP(key.key.handle, _alg);
        return wrappedKey;
    }

    static unwrapKey(wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: aes.IAesKeyGenParams, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(unwrapAlgorithm);
        this.checkAlgorithmHashedParams(unwrapAlgorithm);
        this.checkPrivateKey(unwrappingKey);

        let _alg = this.wc2ssl(unwrapAlgorithm);

        // convert unwrappedAlgorithm to PKCS11 Algorithm
        let AlgClass = null;
        switch (unwrappedAlgorithm.name) {
            // case aes.ALG_NAME_AES_CTR:
            // case aes.ALG_NAME_AES_CMAC:
            // case aes.ALG_NAME_AES_CFB:
            // case aes.ALG_NAME_AES_KW:
            case aes.ALG_NAME_AES_CBC:
                aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
                AlgClass = aes.AesCBC;
                break;
            /*
            case aes.ALG_NAME_AES_GCM:
                aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
                AlgClass = aes.AesGCM;
                break;
            */
            default:
                throw new Error("Unsupported algorithm in use");

        }

        let unwrappedKey: Buffer = unwrappingKey.key.decryptRsaOAEP(wrappedKey, _alg);
        return new AlgClass(unwrappedKey, unwrappedAlgorithm);
    }
}