interface NodeCrypto extends Crypto {
    keyStorage: NodeKeyStorage;
}

interface NodeKeyStorage {
    length: number;
    clear(): void;
    getItem(key: string): CryptoKey;
    removeItem(key: string): void;
    setItem(key: string, data: CryptoKey): void;
}

type NodeCryptoBuffer = Buffer | ArrayBufferView;

interface NodeAlgorithm extends Algorithm {
    name: string;
    hash?: NodeAlgorithm;
    [key: string]: any;
}

type TAlgorithm = string | NodeAlgorithm;

interface JWK {
    [key: string]: any;
}

interface NodeSubtleCrypto extends SubtleCrypto {
    generateKey(algorithm: TAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
    digest(algorithm: TAlgorithm, data: NodeCryptoBuffer): PromiseLike<ArrayBuffer>;
    sign(algorithm: TAlgorithm, key: CryptoKey, data: NodeCryptoBuffer): PromiseLike<ArrayBuffer>;
    verify(algorithm: TAlgorithm, key: CryptoKey, signature: NodeCryptoBuffer, data: NodeCryptoBuffer): PromiseLike<boolean>;
    encrypt(algorithm: TAlgorithm, key: CryptoKey, data: NodeCryptoBuffer): PromiseLike<ArrayBuffer>;
    decrypt(algorithm: TAlgorithm, key: CryptoKey, data: NodeCryptoBuffer): PromiseLike<ArrayBuffer>;
    deriveBits(algorithm: TAlgorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    deriveKey(algorithm: TAlgorithm, baseKey: CryptoKey, derivedKeyType: TAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    exportKey(format: string, key: CryptoKey): PromiseLike<JWK | ArrayBuffer>;
    importKey(format: string, keyData: JWK | NodeCryptoBuffer, algorithm: TAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: TAlgorithm): PromiseLike<ArrayBuffer>;
    unwrapKey(format: string, wrappedKey: NodeCryptoBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: TAlgorithm, unwrappedKeyAlgorithm: TAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
}

declare type NodeCryptoKey = CryptoKey;
declare type NodeCryptoKeyPair = CryptoKeyPair;