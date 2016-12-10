// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;
const BaseCrypto = webcrypto.BaseCrypto;
const Base64Url = webcrypto.Base64Url;

// Local
import { CryptoKey } from "../key";
import * as native from "../native";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

export abstract class RsaCrypto extends BaseCrypto {

    static generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<any> {
        return new Promise((resolve, reject) => {
            let size = algorithm.modulusLength;
            let exp = new Buffer(algorithm.publicExponent);
            // convert exp
            let nExp: number = 0;
            if (exp.length === 3)
                nExp = 1;
            native.Key.generateRsa(size, nExp, (err, key) => {
                try {
                    if (err) {
                        reject(new WebCryptoError(`Rsa: Can not generate new key\n${err.message}`));
                    }
                    else {
                        const prvUsages = ["sign", "decrypt", "unwrapKey"]
                            .filter(usage => keyUsages.some(keyUsage => keyUsage === usage));
                        const pubUsages = ["verify", "encrypt", "wrapKey"]
                            .filter(usage => keyUsages.some(keyUsage => keyUsage === usage));
                        resolve({
                            privateKey: new CryptoKey(key, algorithm, "private", extractable, prvUsages),
                            publicKey: new CryptoKey(key, algorithm, "public", extractable, pubUsages)
                        });
                    }
                }
                catch (e) {
                    reject(e);
                }
            });
        });
    }

    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let _format = format.toLocaleLowerCase();
            const alg = algorithm as Algorithm;
            switch (_format) {
                case "jwk":
                    const jwk = keyData as JsonWebKey;
                    const data: { [key: string]: Buffer } = {};
                    // prepare data
                    data["kty"] = jwk.kty as any;
                    data["n"] = b64_decode(jwk.n!);
                    data["e"] = b64_decode(jwk.e!);
                    let key_type = native.KeyType.PUBLIC;
                    if (jwk.d) {
                        key_type = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d!);
                        data["p"] = b64_decode(jwk.p!);
                        data["q"] = b64_decode(jwk.q!);
                        data["dp"] = b64_decode(jwk.dp!);
                        data["dq"] = b64_decode(jwk.dq!);
                        data["qi"] = b64_decode(jwk.qi!);
                    }
                    native.Key.importJwk(data, key_type, (err, key) => {
                        try {
                            if (err)
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            else {
                                let rsa = new CryptoKey(key, alg, key_type ? "private" : "public", extractable, keyUsages);
                                resolve(rsa);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "pkcs8":
                case "spki":
                    if (!Buffer.isBuffer(keyData))
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    let importFunction = native.Key.importPkcs8;
                    if (_format === "spki")
                        importFunction = native.Key.importSpki;
                    importFunction(<Buffer>keyData, (err, key) => {
                        try {
                            if (err)
                                reject(new WebCryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
                            else {
                                let rsa = new CryptoKey(key, alg, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                                resolve(rsa);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
        });
    }

    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let nkey = <native.Key>key.native;
            let type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nkey.exportJwk(type, (err, data) => {
                        try {
                            let jwk: JsonWebKey = { kty: "RSA" };
                            jwk.key_ops = key.usages;

                            // convert base64 -> base64url for all props
                            jwk.e = Base64Url.encode(data.e);
                            jwk.n = Base64Url.encode(data.n);
                            if (key.type === "private") {
                                jwk.d = Base64Url.encode(data.d);
                                jwk.p = Base64Url.encode(data.p);
                                jwk.q = Base64Url.encode(data.q);
                                jwk.dp = Base64Url.encode(data.dp);
                                jwk.dq = Base64Url.encode(data.dq);
                                jwk.qi = Base64Url.encode(data.qi);
                            }
                            resolve(jwk);
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "spki":
                    nkey.exportSpki((err, raw) => {
                        if (err)
                            reject(err);
                        else
                            resolve(raw.buffer);
                    });
                    break;
                case "pkcs8":
                    nkey.exportPkcs8((err, raw) => {
                        if (err)
                            reject(err);
                        else
                            resolve(raw.buffer);
                    });
                    break;
                default:
                    throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    static wc2ssl(alg: any) {
        let _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    }
}

export class RsaPKCS1 extends RsaCrypto {

    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    let reg = /(\d+)$/;
                    jwk.alg = "RS" + reg.exec((key.algorithm as any).hash.name) ![1];
                    jwk.ext = true;
                    if (key.type === "public") {
                        jwk.key_ops = ["verify"];
                    }
                }
                return jwk;
            });
    }

    static sign(algorithm: any, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.sign(_alg, data, (err, signature) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else {
                    resolve(signature.buffer);
                }
            });
        });
    }

    static verify(algorithm: any, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.verify(_alg, data, signature, (err, res) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else
                    resolve(res);
            });
        });
    }

}

export class RsaPSS extends RsaCrypto {

    static sign(algorithm: RsaPSS, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.RsaPssSign(_alg, _alg.saltLength / 8, data, (err, signature) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else
                    resolve(signature.buffer);
            });
        });
    }

    static verify(algorithm: RsaPSS, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            nkey.RsaPssVerify(_alg, _alg.saltLength / 8, data, signature, (err, res) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else
                    resolve(res);
            });
        });
    }

    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    let reg = /(\d+)$/;
                    jwk.alg = "PS" + reg.exec((key.algorithm as any).hash.name) ![1];
                    jwk.ext = true;
                    if (key.type === "public") {
                        jwk.key_ops = ["verify"];
                    }
                }
                return jwk;
            });
    }

}

export class RsaOAEP extends RsaCrypto {

    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    jwk.alg = "RSA-OAEP";
                    let md_size = /(\d+)$/.exec((key.algorithm as any).hash.name) ![1];
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
                }
                return jwk;
            });
    }

    protected static EncryptDecrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer, type: boolean): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(key.algorithm);
            let nkey = key.native as native.Key;

            let label: Buffer | null = null;
            if (algorithm.label) {
                label = new Buffer(algorithm.label as Uint8Array);
            }

            nkey.RsaOaepEncDec(_alg, data, label, type, (err, res) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err));
                else
                    resolve(res.buffer);
            });
        });
    }

    static encrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, false);
    }

    static decrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, true);
    }

}
