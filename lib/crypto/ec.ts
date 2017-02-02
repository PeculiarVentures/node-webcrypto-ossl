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
            throw new WebCryptoError("Unsupported namedCurve in use");
    }
    return (native.EcNamedCurves as any)[_namedCurve];
}

function b64_decode(b64url: string): Buffer {
    return new Buffer(Base64Url.decode(b64url));
}

function buf_pad(buf: Buffer, padSize: number = 0) {
    if (padSize && Buffer.length < padSize) {
        let pad = new Buffer(new Uint8Array(padSize - buf.length).map(v => 0));
        return Buffer.concat([pad, buf]);
    }
    return buf;
}

export class EcCrypto extends BaseCrypto {

    static generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            const _algorithm = algorithm as EcKeyGenParams;
            let namedCurve = nc2ssl(_algorithm.namedCurve);

            native.Key.generateEc(namedCurve, (err, key) => {
                if (err) reject(err);
                else {
                    const prvUsages = ["sign", "deriveKey", "deriveBits"]
                        .filter(usage => keyUsages.some(keyUsage => keyUsage === usage));
                    const pubUsages = ["verify"]
                        .filter(usage => keyUsages.some(keyUsage => keyUsage === usage));
                    resolve({
                        privateKey: new CryptoKey(key, algorithm, "private", extractable, prvUsages),
                        publicKey: new CryptoKey(key, algorithm, "public", true, pubUsages)
                    });
                }
            });
        });
    }

    static importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let _format = format.toLocaleLowerCase();
            const alg = algorithm as Algorithm;
            const data: { [key: string]: Buffer } = {};            
            let key_type = native.KeyType.PUBLIC;
            switch (_format) {
                case "raw":
                    if (!Buffer.isBuffer(keyData))
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");

                    let keyLength = 0;
                    let crv = "";

                    if(keyData.length === 65) {
                        // P-256
                        crv = "P-256";
                        // Key length 32 Byte
                        keyLength = 32;
                    } else if(keyData.length === 97) {
                        // P-384
                        crv = "P-384";
                        // Key length 48 Byte
                        keyLength = 48;
                    } else if(keyData.length === 133) {
                        // P-521
                        crv = "P-521";
                        // Key length: 521/= 65,125 => 66 Byte
                        keyLength = 66;
                    }

                    let x = keyData.slice(1, keyLength + 1);
                    let y = keyData.slice(keyLength + 1, (keyLength * 2) + 1);

                    data["kty"] =  new Buffer ("EC", "utf-8");
                    data["crv"] = nc2ssl(crv);
                    data["x"] = b64_decode(Base64Url.encode(buf_pad(x, keyLength)));
                    data["y"] = b64_decode(Base64Url.encode(buf_pad(y, keyLength)));

                    native.Key.importJwk(data, key_type, (err, key) => {
                        try {
                            if (err)
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            else {
                                let ec = new CryptoKey(key, alg, key_type ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });

                  break
                case "jwk":
                    const jwk = keyData as JsonWebKey;
                    // prepare data
                    data["kty"] = jwk.kty as any;
                    data["crv"] = nc2ssl(jwk.crv);
                    data["x"] = b64_decode(jwk.x!);
                    data["y"] = b64_decode(jwk.y!);
                    if (jwk.d) {
                        key_type = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d!);
                    }
                    native.Key.importJwk(data, key_type, (err, key) => {
                        try {
                            if (err)
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            else {
                                let ec = new CryptoKey(key, alg, key_type ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
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
                                let ec = new CryptoKey(key, alg, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                                resolve(ec);
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

    static exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    static exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let nkey = <native.Key>key.native;
            let type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nkey.exportJwk(type, (err, data) => {
                        try {
                            let jwk: JsonWebKey = { kty: "EC" };
                            jwk.crv = (key.algorithm as any).namedCurve;
                            jwk.key_ops = key.usages;
                            // convert base64 -> base64url for all props
                            let padSize = 0;
                            switch (jwk.crv) {
                                // case "P-251":
                                // break;
                                // case "P-384":
                                // break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                            }
                            jwk.x = Base64Url.encode(buf_pad(data.x, padSize));
                            jwk.y = Base64Url.encode(buf_pad(data.y, padSize));
                            if (key.type === "private") {
                                jwk.d = Base64Url.encode(buf_pad(data.d, padSize));
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
                case "raw":
                    nkey.exportJwk(type, (err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            let padSize = 0;

                            let crv = (key.algorithm as any).namedCurve;                            

                            switch (crv) {
                                case "P-256":
                                    padSize = 32;
                                    break;
                                case "P-384":
                                    padSize = 48;
                                    break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                            }

                            let x = Base64Url.decode(Base64Url.encode(buf_pad(data.x, padSize)));
                            let y = Base64Url.decode(Base64Url.encode(buf_pad(data.y, padSize)));

                            var rawKey = new Uint8Array(1 + x.length + y.length);
                            rawKey.set([4]);
                            rawKey.set(x, 1);
                            rawKey.set(y, 1 + x.length);

                            resolve(rawKey.buffer);
                        }
                    });
                    break
                default:
                    throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }

    static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(algorithm);
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

    static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            let _alg = this.wc2ssl(algorithm);
            let nkey = key.native as native.Key;

            nkey.verify(_alg, data, signature, (err, res) => {
                if (err)
                    reject(new WebCryptoError("NativeError: " + err.message));
                else
                    resolve(res);
            });
        });
    }

    static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const _derivedKeyType = derivedKeyType as AesDerivedKeyParams;
            const _algorithm = algorithm as EcdhKeyDeriveParams;

            let AesClass: typeof aes.AesCrypto;
            switch (_derivedKeyType.name.toLowerCase()) {
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AesClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _derivedKeyType.name);
            }

            // derive key
            (baseKey.native as native.Key).EcdhDeriveKey((_algorithm.public as any).native, _derivedKeyType.length / 8, (err, raw) => {
                if (err) reject(err);
                else {
                    AesClass.importKey("raw", raw, _derivedKeyType, extractable, keyUsages)
                        .then(resolve, reject);
                }
            });
        });
    }

    static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const _algorithm = algorithm as EcdhKeyDeriveParams;
            // derive bits
            (<native.Key>baseKey.native).EcdhDeriveBits((_algorithm.public as any).native, length, (err, raw) => {
                if (err) reject(err);
                else
                    resolve(raw.buffer);
            });
        });
    }

    static wc2ssl(alg: EcdsaParams) {
        let _alg = (alg.hash as Algorithm).name.toUpperCase().replace("-", "");
        return _alg;
    }
}
