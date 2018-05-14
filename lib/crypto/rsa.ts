// Core
import { Base64Url, BaseCrypto, WebCryptoError } from "webcrypto-core";

// Local
import { CryptoKey } from "../key";
import * as native from "../native";

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

export abstract class RsaCrypto extends BaseCrypto {

    public static generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<any> {
        return new Promise((resolve, reject) => {
            const size = algorithm.modulusLength;
            const exp = new Buffer(algorithm.publicExponent);
            // convert exp
            let nExp: number = 0;
            if (exp.length === 3) {
                nExp = 1;
            }
            native.Key.generateRsa(size, nExp, (err, key) => {
                try {
                    if (err) {
                        reject(new WebCryptoError(`Rsa: Can not generate new key\n${err.message}`));
                    } else {
                        const prvUsages = ["sign", "decrypt", "unwrapKey"]
                            .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                        const pubUsages = ["verify", "encrypt", "wrapKey"]
                            .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                        resolve({
                            privateKey: new CryptoKey(key, algorithm, "private", extractable, prvUsages),
                            publicKey: new CryptoKey(key, algorithm, "public", true, pubUsages),
                        });
                    }
                } catch (e) {
                    reject(e);
                }
            });
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        let keyType = native.KeyType.PUBLIC;
        const alg: any = algorithm;
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            switch (formatLC) {
                case "jwk":
                    const jwk = keyData as JsonWebKey;
                    const data: { [key: string]: Buffer } = {};
                    // prepare data
                    data["kty"] = jwk.kty as any;
                    data["n"] = b64_decode(jwk.n!);
                    data["e"] = b64_decode(jwk.e!);
                    if (jwk.d) {
                        keyType = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d!);
                        data["p"] = b64_decode(jwk.p!);
                        data["q"] = b64_decode(jwk.q!);
                        data["dp"] = b64_decode(jwk.dp!);
                        data["dq"] = b64_decode(jwk.dq!);
                        data["qi"] = b64_decode(jwk.qi!);
                    }
                    native.Key.importJwk(data, keyType, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            } else {
                                resolve(key);
                            }
                        } catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "pkcs8":
                case "spki":
                    if (!Buffer.isBuffer(keyData)) {
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    let importFunction = native.Key.importSpki;
                    if (formatLC === "pkcs8") {
                        keyType = native.KeyType.PRIVATE;
                        importFunction = native.Key.importPkcs8;
                    }
                    importFunction(<Buffer>keyData, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
                            } else {
                                resolve(key);
                            }
                        } catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
        })
            .then((key: native.Key) => {
                alg.modulusLength = key.modulusLength() << 3;
                alg.publicExponent = new Uint8Array(key.publicExponent());
                return new CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
            });
    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const nativeKey = <native.Key>key.native;
            const type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nativeKey.exportJwk(type, (err, data) => {
                        try {
                            const jwk: JsonWebKey = { kty: "RSA" };
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
                        } catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "spki":
                    nativeKey.exportSpki((err, raw) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(raw.buffer as ArrayBuffer);
                        }
                    });
                    break;
                case "pkcs8":
                    nativeKey.exportPkcs8((err, raw) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(raw.buffer as ArrayBuffer);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    public static wc2ssl(algorithm: any) {
        const alg = algorithm.hash.name.toUpperCase().replace("-", "");
        return alg;
    }
}

export class RsaPKCS1 extends RsaCrypto {

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    const reg = /(\d+)$/;
                    jwk.alg = "RS" + reg.exec((key.algorithm as any).hash.name)![1];
                    jwk.ext = true;
                    if (key.type === "public") {
                        jwk.key_ops = ["verify"];
                    }
                }
                return jwk;
            });
    }

    public static sign(algorithm: any, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.sign(alg, data, (err, signature) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(signature.buffer as ArrayBuffer);
                }
            });
        });
    }

    public static verify(algorithm: any, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.verify(alg, data, signature, (err, res) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(res);
                }
            });
        });
    }

}

export class RsaPSS extends RsaCrypto {

    public static sign(algorithm: RsaPSS, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.RsaPssSign(alg, (algorithm as any).saltLength, data, (err, signature) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(signature.buffer as ArrayBuffer);
                }
            });
        });
    }

    public static verify(algorithm: RsaPSS, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.RsaPssVerify(alg, (algorithm as any).saltLength, data, signature, (err, res) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(res);
                }
            });
        });
    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    const reg = /(\d+)$/;
                    jwk.alg = "PS" + reg.exec((key.algorithm as any).hash.name)![1];
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

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey(format, key)
            .then((jwk: JsonWebKey) => {
                if (format === "jwk") {
                    jwk.alg = "RSA-OAEP";
                    const mdSize = /(\d+)$/.exec((key.algorithm as any).hash.name)![1];
                    if (mdSize !== "1") {
                        jwk.alg += "-" + mdSize;
                    }
                    jwk.ext = true;
                    if (key.type === "public") {
                        jwk.key_ops = ["encrypt", "wrapKey"];
                    } else {
                        jwk.key_ops = ["decrypt", "unwrapKey"];
                    }
                }
                return jwk;
            });
    }

    public static encrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, false);
    }

    public static decrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return this.EncryptDecrypt(algorithm, key, data, true);
    }

    protected static EncryptDecrypt(algorithm: RsaOaepParams, key: CryptoKey, data: Buffer, type: boolean): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native as native.Key;

            let label: Buffer | null = null;
            if (algorithm.label) {
                label = new Buffer(algorithm.label as Uint8Array);
            }

            nativeKey.RsaOaepEncDec(alg, data, label, type, (err, res) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err));
                } else {
                    resolve(res.buffer as ArrayBuffer);
                }
            });
        });
    }

}
