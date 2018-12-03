/// <reference types="node" />
/// <reference types="webcrypto-core" />
/// <reference lib="dom" />

declare namespace NodeWebcryptoOpenSSL {

    type NodeBufferSource = BufferSource | Buffer;

    enum EcNamedCurves {
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
        sect571r1 = 734,
    }

    enum RsaPublicExponent {
        RSA_3 = 0,
        RSA_F4 = 1,
    }

    class Key {
        public static generateRsa(modulus: number, publicExponent: RsaPublicExponent, callback: (err: Error, key: Key) => void): void;
        public static generateEc(namedCurve: EcNamedCurves, callback: (err: Error, key: Key) => void): void;
        public static importJwk(jwk: Object, keyType: KeyType, callback: (err: Error, key: Key) => void): void;
        public static importJwk(jwk: { [key: string]: Buffer; }, keyType: KeyType): any;
        public static importSpki(raw: Buffer, callback: (err: Error, key: Key) => void): void;
        public static importPkcs8(raw: Buffer, callback: (err: Error, key: Key) => void): void;

        public type: number;

        public modulusLength(): number;
        public publicExponent(): Buffer;
        public exportJwk(keyType: KeyType, callback: (err: Error, jwk: any) => void): void;
        public exportJwk(keyType: KeyType): any;
        public exportSpki(callback: (err: Error, raw: Buffer) => void): void;
        public exportPkcs8(callback: (err: Error, raw: Buffer) => void): void;
        public sign(digestName: string, message: Buffer, callback: (err: Error, signature: Buffer) => void): void;
        public verify(digestName: string, message: Buffer, signature: Buffer, callback: (err: Error, valid: boolean) => void): void;
        public RsaOaepEncDec(digestName: string, data: Buffer, label: Buffer | null, decrypt: boolean, callback: (err: Error, raw: Buffer) => void): void;
        public RsaPssSign(digestName: string, saltLength: number, data: Buffer, cb: (err: Error, signature: Buffer) => void): void;
        public RsaPssVerify(digestName: string, saltLength: number, data: Buffer, signature: Buffer, cb: (err: Error, verified: boolean) => void): void;
        public EcdhDeriveKey(pubkey: Key, derivedLen: number, callback: (err: Error, raw: Buffer) => void): void;
        public EcdhDeriveBits(pubkey: Key, lengthBits: number, callback: (err: Error, raw: Buffer) => void): void;
    }

    class AesKey {
        public static generate(keySize: number, callback: (err: Error, key: AesKey) => void): void;
        public static import(raw: Buffer, callback: (err: Error, key: AesKey) => void): void;
        public encrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
        public encryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
        public decrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
        public decryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
        public export(callback: (err: Error, raw: Buffer) => void): void;
    }

    class Core {
        public static digest(digestName: string, messgae: Buffer, callback: (err: Error, digest: Buffer) => void): void;
    }

    interface CryptoKeyPair extends NativeCryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }

    class CryptoKey implements NativeCryptoKey {
        public type: KeyType;
        public extractable: boolean;
        public algorithm: Algorithm;
        public usages: KeyUsage[];
        public readonly native: AesKey | Key;
        private native_: AesKey | Key;
        constructor(key: AesKey | Key, alg: Algorithm, type: string, extractable: boolean, keyUsages: string[]);
    }

    interface IKeyStorageItem extends NativeCryptoKey {
        name: string;
        keyJwk: any;
        file?: string;
    }

    class KeyStorage {
        public readonly length: number;
        protected directory: string;
        protected keys: {
            [key: string]: IKeyStorageItem;
        };
        constructor(directory: string);
        public clear(): void;
        public getItem(key: string): CryptoKey | null;
        public key(index: number): string;
        public removeItem(key: string): void;
        public setItem(key: string, data: CryptoKey): void;
        protected getItemById(id: string): IKeyStorageItem;
        protected createDirectory(directory: string, flags?: any): void;
        protected readFile(file: string): IKeyStorageItem | null;
        protected readDirectory(): void;
        protected saveFile(key: IKeyStorageItem): void;
        protected removeFile(key: IKeyStorageItem): void;
    }

    interface WebCryptoOptions {
        directory?: string;
    }

    class SubtleCrypto extends WebcryptoCore.SubtleCrypto {
        public digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
        public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
        public generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
        public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer>;
        public unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
        public exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
        public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
        public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    }

    /**
     * OpenSSL with WebCrypto Interface
     */
    export class WebCrypto implements NativeCrypto {

        public keyStorage: KeyStorage;
        public subtle: SubtleCrypto;

        /**
         * Constructor
         */
        constructor(options?: WebCryptoOptions);

        /**
         * Generates cryptographically random values
         * @param array Initialize array
         */
        public getRandomValues<T extends Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null>(array: T): T;

    }
}

declare const NodeWebCrypto: typeof NodeWebcryptoOpenSSL.WebCrypto;

declare module "node-webcrypto-ossl" {
    export = NodeWebCrypto;
}
