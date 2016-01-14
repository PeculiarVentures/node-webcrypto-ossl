import native from "./native";
import BaseObject from "./object";
import * as crypto from "crypto";
let base64url = require("base64url");

export enum KeyType {
    Private,
    Public,
    Secret
}

export enum EcNamedCurves {
    secp112r1 = 704,
    secp112r2 = 705,
    secp128r1 = 706,
    secp128r2 = 707,
    secp160k1 = 708,
    secp160r1 = 709,
    secp160r2 = 710,
    secp192r1 = 409,
    secp192k1 = 711,
    secp224k1 = 712,
    secp224r1 = 713,
    secp256k1 = 714,
    secp256r1 = 415,
    secp384r1 = 715,
    secp521r1 = 716,
    sect113r1 = 717,
    sect113r2 = 718,
    sect131r1 = 719,
    sect131r2 = 720,
    sect163k1 = 721,
    sect163r1 = 722,
    sect163r2 = 723,
    sect193r1 = 724,
    sect193r2 = 725,
    sect233k1 = 726,
    sect233r1 = 727,
    sect239k1 = 728,
    sect283k1 = 729,
    sect283r1 = 730,
    sect409k1 = 731,
    sect409r1 = 732,
    sect571k1 = 733,
    sect571r1 = 734
}

export class SecretKey extends BaseObject {
    constructor();
    constructor(buf: Buffer);
    constructor(buf?: Buffer) {
        super();

        if (buf) {
            this.handle = buf;
        }
    }

    /**
     * Returns size of key in bits
     */
    get size(): number {
        return this.handle.length * 8;
    }

    /**
     * Generates AES key
     * @param len Size of key in bits
     */
    static generateAes(len: number) {
        let key = crypto.randomBytes(len / 8);
        let skey = new SecretKey();
        skey.handle = key;
        return skey;
    }
}

export class KeyPair extends BaseObject {
    constructor() {
        super();
        this.handle = new native.Pki.Key();
    }

    static generateRsa(m, e): KeyPair {
        let key = new KeyPair();
        key.handle.generateRsa(m, e);
        return key;
    }

    static generateEc(namedCurve: string): KeyPair {
        if (!EcNamedCurves[namedCurve])
            throw new TypeError(`Parameter: namedCurve: Wrong value '${namedCurve}'`);
        let key = new KeyPair();
        key.handle.generateEc(EcNamedCurves[namedCurve]);
        return key;
    }

    export(type: KeyType = KeyType.Public): Buffer {
        throw new Error("Not supported in current implementation");
        let res: Buffer;
        switch (type) {
            case KeyType.Private:
                res = this.handle.writePrivateKey();
                break;
            case KeyType.Public:
                res = this.handle.exportRsa();
                break;
            case KeyType.Secret:
                throw new Error("Not supported in current implementation");
            default:
                throw new Error("Unknown KeyType in use");
        }
        return res;
    }

    private checkType(type: string): void {
        let res: boolean = false;
        switch (type.toUpperCase()) {
            case "RSA":
                res = this.type === 6;
                break;
            default:
                throw new Error(`Unknown '${type}' key type in use`);
        }
        if (!res)
            throw new Error(`Wrong key type in use. Must be '${type}'`);
    }

    exportJwk(part: string) {
        return buf2base64(this.handle.exportJWK(part));
    }

    importJwk(type: string, part: string, data: any): KeyPair {
        this.handle.importJWK(type, part, data);
        return this;
    }

    writeSpki(format: string): Buffer {
        format = format.toLowerCase();
        return this.handle.writeSPKI(format);
    }

    writePkcs8(format: string): Buffer;
    writePkcs8(format: string, pass: string, salt: Buffer, iter: number): Buffer;
    writePkcs8(format: string, pass?: string, salt?: Buffer, iter?: number): Buffer {
        format = format.toLowerCase();
        if (!pass) {
            return this.handle.writePKCS8(format);
        }
        else {
            return this.handle.writePKCS8(format, pass, salt, iter);
        }
    }

    static readSpki(buf: Buffer, format: string): KeyPair {
        let key = new KeyPair();
        key.readSpki(buf, format);
        return key;
    }

    readSpki(buf: Buffer, format: string) {
        format = format.toLowerCase();
        this.handle.readSPKI(buf, format);
    }

    static readPkcs8(buf: Buffer, format: string): KeyPair {
        let key = new KeyPair();
        key.readPkcs8(buf, format);
        return key;
    }

    readPkcs8(buf: Buffer, format: string) {
        format = format.toLowerCase();
        this.handle.readPKCS8(buf, format);
    }

    encryptRsaOAEP(data: Buffer, hash: string = "SHA1", label?: Buffer) {
        this.checkType("RSA");
        return this.handle.encryptRsaOAEP(data, hash, label);
    }

    decryptRsaOAEP(data: Buffer, hash: string = "SHA1", label?: Buffer) {
        this.checkType("RSA");
        return this.handle.decryptRsaOAEP(data, hash, label);
    }

    get type(): number {
        return this.handle.type;
    }
}

function buf2base64(o) {
    if (typeof (o) === "object") {
        if (Buffer.isBuffer(o)) {
            return base64url(o, "binary");
        }
        else {
            for (let i in o) {
                o[i] = buf2base64(o[i]);
            }
        }
    }
    return o;
}

export function sign(key: KeyPair, data: Buffer, digestName: string = "SHA1"): Buffer {
    return native.Pki.sign(key.handle, data, digestName);
}

export function verify(key: KeyPair, data: Buffer, sig: Buffer, digestName: string = "SHA1"): boolean {
    return native.Pki.verify(key.handle, data, sig, digestName);
}

export function deriveKey(privateKey: KeyPair, publicKey: KeyPair, keySize: number): Buffer {
    return native.Pki.deriveKey(privateKey.handle, publicKey.handle, keySize);
}