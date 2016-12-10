/// <reference types="node" />
/// <reference types="webcrypto-core" />

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

    enum KeyType {
        PUBLIC = 0,
        PRIVATE = 1,
    }

    class Key {
        type: number;
        modulusLength(): number;
        publicExponent(): Buffer;
        exportJwk(keyType: KeyType, callback: (err: Error, jwk: any) => void): void;
        exportJwk(keyType: KeyType): any;
        exportSpki(callback: (err: Error, raw: Buffer) => void): void;
        exportPkcs8(callback: (err: Error, raw: Buffer) => void): void;
        sign(digestName: string, message: Buffer, callback: (err: Error, signature: Buffer) => void): void;
        verify(digestName: string, message: Buffer, signature: Buffer, callback: (err: Error, valid: boolean) => void): void;
        RsaOaepEncDec(digestName: string, data: Buffer, label: Buffer | null, decrypt: boolean, callback: (err: Error, raw: Buffer) => void): void;
        RsaPssSign(digestName: string, saltLength: number, data: Buffer, cb: (err: Error, signature: Buffer) => void): void;
        RsaPssVerify(digestName: string, saltLength: number, data: Buffer, signature: Buffer, cb: (err: Error, verified: boolean) => void): void;
        EcdhDeriveKey(pubkey: Key, derivedLen: number, callback: (err: Error, raw: Buffer) => void): void;
        EcdhDeriveBits(pubkey: Key, lengthBits: number, callback: (err: Error, raw: Buffer) => void): void;
        static generateRsa(modulus: number, publicExponent: RsaPublicExponent, callback: (err: Error, key: Key) => void): void;
        static generateEc(namedCurve: EcNamedCurves, callback: (err: Error, key: Key) => void): void;
        static importJwk(jwk: Object, keyType: KeyType, callback: (err: Error, key: Key) => void): void;
        static importJwk(jwk: {
            [key: string]: Buffer;
        }, keyType: KeyType): any;
        static importSpki(raw: Buffer, callback: (err: Error, key: Key) => void): void;
        static importPkcs8(raw: Buffer, callback: (err: Error, key: Key) => void): void;
    }

    class AesKey {
        static generate(keySize: number, callback: (err: Error, key: AesKey) => void): void;
        encrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
        encryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
        decrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
        decryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
        export(callback: (err: Error, raw: Buffer) => void): void;
        static import(raw: Buffer, callback: (err: Error, key: AesKey) => void): void;
    }

    class Core {
        static digest(digestName: string, messgae: Buffer, callback: (err: Error, digest: Buffer) => void): void;
    }

    interface CryptoKeyPair extends NativeCryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }

    class CryptoKey implements NativeCryptoKey {
        type: string;
        extractable: boolean;
        algorithm: Algorithm;
        usages: string[];
        private native_: AesKey | Key;
        readonly native: AesKey | Key;
        constructor(key: AesKey | Key, alg: Algorithm, type: string, extractable: boolean, keyUsages: string[]);
    }

    interface IKeyStorageItem extends NativeCryptoKey {
        name: string;
        keyJwk: any;
        file?: string;
    }

    class KeyStorage {
        protected directory: string;
        protected keys: {
            [key: string]: IKeyStorageItem;
        };
        constructor(directory: string);
        protected createDirectory(directory: string, flags?: any): void;
        protected readFile(file: string): IKeyStorageItem | null;
        protected readDirectory(): void;
        protected saveFile(key: IKeyStorageItem): void;
        protected removeFile(key: IKeyStorageItem): void;
        readonly length: number;
        clear(): void;
        protected getItemById(id: string): IKeyStorageItem;
        getItem(key: string): CryptoKey | null;
        key(index: number): string;
        removeItem(key: string): void;
        setItem(key: string, data: CryptoKey): void;
    }

    interface WebCryptoOptions {
        directory?: string;
    }

    class SubtleCrypto extends WebcryptoCore.SubtleCrypto {
        digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
        generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
        generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
        encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer>;
        unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
        exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
        exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
        exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    }

    /**
     * OpenSSL with WebCrypto Interface
     */
    class WebCrypto implements NativeCrypto {

        keyStorage: KeyStorage;
        subtle: SubtleCrypto;

        /**
         * Generates cryptographically random values
         * @param array Initialize array
         */
        getRandomValues(array: NodeBufferSource): NodeBufferSource;
        getRandomValues(array: ArrayBufferView): ArrayBufferView;

        /**
         * Constructor
         */
        constructor(options?: WebCryptoOptions);
    }
}

declare module "node-webcrypto-ossl" {
    export = NodeWebcryptoOpenSSL.WebCrypto;
}