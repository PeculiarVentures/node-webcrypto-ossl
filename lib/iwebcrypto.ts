export interface IAlgorithmIdentifier {
    name: string;
    hash?: IAlgorithmIdentifier;
}

export type AlgorithmType = string | IAlgorithmIdentifier;

export interface IWebCrypto {
    subtle: ISubtleCrypto;
    getRandomValues(array: ArrayBufferView): Buffer;
}

export type TBuffer = ArrayBuffer | Buffer;

export interface ISubtleCrypto {
    digest(algorithm: IAlgorithmIdentifier, data: TBuffer): PromiseLike<ArrayBufferView>;
    generateKey(algorithm: AlgorithmType, extractable: boolean, keyUsages: string[]): PromiseLike<ICryptoKeyPair>;
    sign(algorithm: AlgorithmType, key: ICryptoKey, data: TBuffer): PromiseLike<ArrayBufferView>;
    verify(algorithm: AlgorithmType, key: CryptoKey, signature: TBuffer, data: TBuffer): PromiseLike<boolean>;
    encrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): PromiseLike<ArrayBufferView>;
    decrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): PromiseLike<ArrayBufferView>;
    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: IAlgorithmIdentifier): PromiseLike<ArrayBufferView>;
    unwrapKey(format: string, wrappedKey: TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAlgorithmIdentifier, unwrappedAlgorithm: IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<ICryptoKey>;
    exportKey(format: string, key: CryptoKey): PromiseLike<any>;
    importKey(
        format: string,
        keyData: TBuffer,
        algorithm: IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): PromiseLike<ICryptoKey>;
    deriveBits(algorithm: string | Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBufferView>;
    deriveKey(algorithm: string | Algorithm, baseKey: CryptoKey, derivedKeyType: string | Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<ICryptoKey>;
}

export var KeyType = ["public", "private", "secret"];

export var KeyUsage = ["encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey", "unwrapKey"];

export interface ICryptoKey {
    type: string;
    extractable: boolean;
    algorithm: any;
    usages: string[];
}

export interface ICryptoKeyPair {
    publicKey: ICryptoKey;
    privateKey: ICryptoKey;
}