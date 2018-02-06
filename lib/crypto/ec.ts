// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const BaseCrypto = webcrypto.BaseCrypto;
const Base64Url = webcrypto.Base64Url;

// Local
import { CryptoKey } from "../key";
import * as native from "../native";
import * as aes from "./aes";

function nc2ssl(nc: any) {
    let namedCurve = "";
    switch (nc.toUpperCase()) {
        case "P-192":
            namedCurve = "secp192r1";
            break;
        case "P-256":
            namedCurve = "secp256r1";
            break;
        case "P-384":
            namedCurve = "secp384r1";
            break;
        case "P-521":
            namedCurve = "secp521r1";
            break;
        case "K-256":
            namedCurve = "secp256k1";
            break;
        default:
            throw new WebCryptoError("Unsupported namedCurve in use");
    }
    return (native.EcNamedCurves as any)[namedCurve];
}

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

function buf_pad(buf: Buffer, padSize: number = 0) {
    if (padSize && Buffer.length < padSize) {
        const pad = new Buffer(new Uint8Array(padSize - buf.length).map((v) => 0));
        return Buffer.concat([pad, buf]);
    }
    return buf;
}

export class EcCrypto extends BaseCrypto {

    public static generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            const alg = algorithm as EcKeyGenParams;
            const namedCurve = nc2ssl(alg.namedCurve);

            native.Key.generateEc(namedCurve, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    const prvUsages = ["sign", "deriveKey", "deriveBits"]
                        .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                    const pubUsages = ["verify"]
                        .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                    resolve({
                        privateKey: new CryptoKey(key, algorithm, "private", extractable, prvUsages),
                        publicKey: new CryptoKey(key, algorithm, "public", true, pubUsages),
                    });
                }
            });
        });
    }

    public static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            const alg = algorithm as EcKeyImportParams;
            const data: { [key: string]: Buffer } = {};
            let keyType = native.KeyType.PUBLIC;
            switch (formatLC) {
                case "raw":
                    if (!Buffer.isBuffer(keyData)) {
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    if (!alg.namedCurve) {
                        throw new WebCryptoError("ImportKey: namedCurve property of algorithm parameter is required");
                    }

                    let keyLength = 0;

                    if (keyData.length === 65) {
                        // P-256
                        // Key length 32 Byte
                        keyLength = 32;
                    } else if (keyData.length === 97) {
                        // P-384
                        // Key length 48 Byte
                        keyLength = 48;
                    } else if (keyData.length === 133) {
                        // P-521
                        // Key length: 521/= 65,125 => 66 Byte
                        keyLength = 66;
                    }

                    const x = keyData.slice(1, keyLength + 1);
                    const y = keyData.slice(keyLength + 1, (keyLength * 2) + 1);

                    data["kty"] = new Buffer("EC", "utf-8");
                    data["crv"] = nc2ssl(alg.namedCurve.toUpperCase());
                    data["x"] = b64_decode(Base64Url.encode(buf_pad(x, keyLength)));
                    data["y"] = b64_decode(Base64Url.encode(buf_pad(y, keyLength)));

                    native.Key.importJwk(data, keyType, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            } else {
                                const ec = new CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
                            }
                        } catch (e) {
                            reject(e);
                        }
                    });

                    break;
                case "jwk":
                    const jwk = keyData as JsonWebKey;
                    // prepare data
                    data["kty"] = jwk.kty as any;
                    data["crv"] = nc2ssl(jwk.crv);
                    data["x"] = b64_decode(jwk.x!);
                    data["y"] = b64_decode(jwk.y!);
                    if (jwk.d) {
                        keyType = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d!);
                    }
                    native.Key.importJwk(data, keyType, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            } else {
                                const ec = new CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
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
                    let importFunction = native.Key.importPkcs8;
                    if (formatLC === "spki") {
                        importFunction = native.Key.importSpki;
                    }
                    importFunction(keyData as Buffer, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
                            } else {
                                const ec = new CryptoKey(key, alg, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                                resolve(ec);
                            }
                        } catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
        });
    }

    public static exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    public static exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native as native.Key;
            const type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nativeKey.exportJwk(type, (err, data) => {
                        try {
                            const jwk: JsonWebKey = { kty: "EC" };
                            jwk.crv = (key.algorithm as any).namedCurve;
                            jwk.key_ops = key.usages;
                            // convert base64 -> base64url for all props
                            let padSize = 0;
                            switch (jwk.crv) {
                                case "P-256":
                                case "K-256":
                                    padSize = 32;
                                    break;
                                case "P-384":
                                    padSize = 48;
                                    break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                                default:
                                    throw new Error(`Unsupported named curve '${jwk.crv}'`);
                            }
                            jwk.x = Base64Url.encode(buf_pad(data.x, padSize));
                            jwk.y = Base64Url.encode(buf_pad(data.y, padSize));
                            if (key.type === "private") {
                                jwk.d = Base64Url.encode(buf_pad(data.d, padSize));
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
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "pkcs8":
                    nativeKey.exportPkcs8((err, raw) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.exportJwk(type, (err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            let padSize = 0;

                            const crv = (key.algorithm as any).namedCurve;

                            switch (crv) {
                                case "P-256":
                                case "K-256":
                                    padSize = 32;
                                    break;
                                case "P-384":
                                    padSize = 48;
                                    break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                                default:
                                    throw new Error(`Unsupported named curve '${crv}'`);
                            }

                            const x = Base64Url.decode(Base64Url.encode(buf_pad(data.x, padSize)));
                            const y = Base64Url.decode(Base64Url.encode(buf_pad(data.y, padSize)));

                            const rawKey = new Uint8Array(1 + x.length + y.length);
                            rawKey.set([4]);
                            rawKey.set(x, 1);
                            rawKey.set(y, 1 + x.length);

                            resolve(rawKey.buffer);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    public static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(algorithm);
            const nativeKey = key.native as native.Key;

            nativeKey.sign(alg, data, (err, signature) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                } else {
                    resolve(signature.buffer);
                }
            });
        });
    }

    public static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(algorithm);
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

    public static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const algDerivedKeyType = derivedKeyType as AesDerivedKeyParams;
            const alg = algorithm as EcdhKeyDeriveParams;

            let AesClass: typeof aes.AesCrypto;
            switch (algDerivedKeyType.name.toLowerCase()) {
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AesClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algDerivedKeyType.name);
            }

            // derive key
            (baseKey.native as native.Key).EcdhDeriveKey((alg.public as any).native, algDerivedKeyType.length / 8, (err, raw) => {
                if (err) {
                    reject(err);
                } else {
                    AesClass.importKey("raw", raw, algDerivedKeyType, extractable, keyUsages)
                        .then(resolve, reject);
                }
            });
        });
    }

    public static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const alg = algorithm as EcdhKeyDeriveParams;
            const nativeKey = baseKey.native as native.Key;
            // derive bits
            nativeKey.EcdhDeriveBits((alg.public as any).native, length, (err, raw) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(raw.buffer);
                }
            });
        });
    }

    public static wc2ssl(algorithm: EcdsaParams) {
        const alg = (algorithm.hash as Algorithm).name.toUpperCase().replace("-", "");
        return alg;
    }
}
