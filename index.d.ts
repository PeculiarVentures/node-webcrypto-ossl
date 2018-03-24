/// <reference types="node" />
/// <reference types="webcrypto-core" />

declare namespace NodeWebcryptoOpenSSL {

    type NodeBufferSource = BufferSource | Buffer;

    interface CryptoKeyPair extends NativeCryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }

    interface NativeKey { }

    class CryptoKey implements NativeCryptoKey {
        public type: string;
        public extractable: boolean;
        public algorithm: Algorithm;
        public usages: string[];
        constructor(key: NativeKey, alg: Algorithm, type: string, extractable: boolean, keyUsages: string[]);
    }

    interface KeyStorage {
        readonly length: number;
        clear(): void;
        getItem(key: string): CryptoKey | null;
        key(index: number): string;
        removeItem(key: string): void;
        setItem(key: string, data: CryptoKey): void;
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
     * OpenSSL with Crypto Interface
     */
    export class Crypto implements NativeCrypto {

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
        public getRandomValues(array: NodeBufferSource): NodeBufferSource;
        public getRandomValues(array: ArrayBufferView): ArrayBufferView;

    }

}

export = NodeWebcryptoOpenSSL;
