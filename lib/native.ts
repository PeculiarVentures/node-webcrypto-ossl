export let Key: INativeKey = require("../build/Debug/nodessl.node").Key;

export enum RsaPublicExponent {
    RSA_3,
    RSA_F4
}

export enum KeyType {
    PUBLIC,
    PRIVATE
}

export interface INativeKey {

    /**
     * Generate RSA key pair
     * @param modulus modulus size of RSA key pair
     * @param publicExponent public exponent of RSA key pair
     * @param callback callback function (err: Error, key: KeyPair)
     */
    generateRsa(modulus: number, publicExponent: RsaPublicExponent, callback: (err: Error, key: NativeKey) => void): void;

    /**
     * create Key from JWK data
     * @param jwk key in JWK format
     * @param keyType type of imported key (PRIVATE or PUBLIC)
     * @param callback
     */
    importJwk(jwk: Object, keyType: KeyType, callback: (err: Error, key: NativeKey) => void): void;

    /**
     * create Key from SPKI
     * @param raw DER data raw
     * @param callback callback function
     */
    importSpki(raw: Buffer, callback: (err: Error, key: NativeKey) => void): void;

    /**
     * create Key from PKCS8
     * @param raw DER data raw
     * @param callback callback function
     */
    importPkcs8(raw: Buffer, callback: (err: Error, key: NativeKey) => void): void;
}

export declare class NativeKey {

    /**
     * type of key
     */
    type: number;

    /**
     * Export Key to JWK data
     * @param keyType type of exported key (PRIVATE or PUBLIC)
     * @param callback Callback function
     */
    exportJwk(keyType: KeyType, callback: (err: Error, jwk: Object) => void): void;

    /**
     * export Key to SPKI
     * @param callback callback function
     */
    exportSpki(callback: (err: Error, raw: Buffer) => void): void;

    /**
     * export Key to PKCS8
     * @param callback callback function
     */
    exportPkcs8(callback: (err: Error, raw: Buffer) => void): void;

    /**
     * sign data
     * @param digestName name of digest algorithm
     * @param message message
     * @param callback callback function
     */
    sign(digestName: string, message: Buffer, callback: (err: Error, signature: Buffer) => void): void

    /**
     * sign data
     * @param digestName name of digest algorithm
     * @param message message
     * @param signature signature from message
     * @param callback callback function
     */
    verify(digestName: string, message: Buffer, signature: Buffer, callback: (err: Error, valid: boolean) => void): void

    /**
     * encrypt/decrypt operation for RSA OAEP key
     * @param digestName name of digest algorithm
     * @param data incoming data 
     * @param label label for operation. Can be NULL
     * @param decrypt type of operation
     * @param callback callback function
     */
    RsaOaepEncDec(digestName: string, data: Buffer, label: Buffer, decrypt: boolean, callback: (err: Error, raw: Buffer) => void): void
}