/// <reference path="./promise.ts" />

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
    digest(algorithm: IAlgorithmIdentifier, data: TBuffer): Promise;
    generateKey(algorithm: AlgorithmType, extractable: boolean, keyUsages: string[]): Promise;
    sign(algorithm: AlgorithmType, key: ICryptoKey, data: TBuffer): Promise;
    verify(algorithm: AlgorithmType, key: CryptoKey, signature: TBuffer, data: TBuffer): Promise;
    encrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): Promise;
    decrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): Promise;
    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: IAlgorithmIdentifier): Promise;
    unwrapKey(format: string, wrappedKey: TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAlgorithmIdentifier, unwrappedAlgorithm: IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
    exportKey(format: string, key: CryptoKey): Promise;
    importKey(
        format: string,
        keyData: TBuffer,
        algorithm: IAlgorithmIdentifier,
        extractable: boolean,
        keyUsages: string[]
    ): Promise;
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