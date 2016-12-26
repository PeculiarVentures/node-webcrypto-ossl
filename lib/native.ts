let native = require("../build/Release/nodessl.node");

export declare enum EcNamedCurves {
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
    sect571r1 = 734
}

export declare enum RsaPublicExponent {
    RSA_3,
    RSA_F4
}

export declare enum KeyType {
    PUBLIC,
    PRIVATE
}

export declare class Key {

    /**
     * type of key
     */
    type: number;

    /**
     * RSA modulus length
     */
    modulusLength(): number;

    /**
     * RSA public exponent
     */
    publicExponent(): Buffer;

    /**
     * Export Key to JWK data
     * @param keyType type of exported key (PRIVATE or PUBLIC)
     * @param callback callback function (err: Error, jwk: Object)
     */
    exportJwk(keyType: KeyType, callback: (err: Error, jwk: any) => void): void;
    /**
     * Export Key to JWK data
     * @param keyType type of exported key (PRIVATE or PUBLIC)
     */
    exportJwk(keyType: KeyType): any;

    /**
     * export Key to SPKI
     * @param callback callback function (err: Error, raw: Buffer)
     */
    exportSpki(callback: (err: Error, raw: Buffer) => void): void;

    /**
     * export Key to PKCS8
     * @param callback callback function (err: Error, raw: Buffer)
     */
    exportPkcs8(callback: (err: Error, raw: Buffer) => void): void;

    /**
     * sign data EC, RSA
     * @param digestName name of digest algorithm
     * @param message message
     * @param callback callback function (err: Error, signature: Buffer)
     */
    sign(digestName: string, message: Buffer, callback: (err: Error, signature: Buffer) => void): void;

    /**
     * verify data RSA, EC
     * @param digestName name of digest algorithm
     * @param message message
     * @param signature signature from message
     * @param callback callback function (err: Error, valid: boolean)
     */
    verify(digestName: string, message: Buffer, signature: Buffer, callback: (err: Error, valid: boolean) => void): void;

    /**
     * encrypt/decrypt operation for RSA OAEP key
     * @param digestName name of digest algorithm
     * @param data incoming data 
     * @param label label for operation. Can be NULL
     * @param decrypt type of operation
     * @param callback callback function (err: Error, raw: Buffer)
     */
    RsaOaepEncDec(digestName: string, data: Buffer, label: Buffer | null, decrypt: boolean, callback: (err: Error, raw: Buffer) => void): void;

    RsaPssSign(digestName: string, saltLength: number, data: Buffer, cb: (err: Error, signature: Buffer) => void): void;
    RsaPssVerify(digestName: string, saltLength: number, data: Buffer, signature: Buffer, cb: (err: Error, verified: boolean) => void): void;

    /**
     * derives key with ECDH
     * @param pubkey public key for key derivation
     * @param derivedLen size of derived key (bytes)
     * @param callback callback function (err: Error, raw: Buffer)
     */
    EcdhDeriveKey(pubkey: Key, derivedLen: number, callback: (err: Error, raw: Buffer) => void): void;

    /**
     * derives bits with ECDH
     * @param pubkey public key for key derivation
     * @param lengthBits the number of bits you want to derive
     * @param callback callback function (err: Error, raw: Buffer)
     */
    EcdhDeriveBits(pubkey: Key, lengthBits: number, callback: (err: Error, raw: Buffer) => void): void;

    /**
     * Generate RSA key pair
     * @param modulus modulus size of RSA key pair
     * @param publicExponent public exponent of RSA key pair
     * @param callback callback function (err: Error, key: Key)
     */
    static generateRsa(modulus: number, publicExponent: RsaPublicExponent, callback: (err: Error, key: Key) => void): void;

    /**
     * Generate EC key pair
     * @param namedCurve NID of curve name
     * @param callback callback function (err: Error, raw: Key)
     */
    static generateEc(namedCurve: EcNamedCurves, callback: (err: Error, key: Key) => void): void;

    /**
     * create Key from JWK data
     * @param jwk key in JWK format
     * @param keyType type of imported key (PRIVATE or PUBLIC)
     * @param callback callback function (err: Error, key: Key)
     */
    static importJwk(jwk: Object, keyType: KeyType, callback: (err: Error, key: Key) => void): void;
    /**
     * create Key from JWK data
     * @param jwk key in JWK format
     * @param keyType type of imported key (PRIVATE or PUBLIC)
     */
    static importJwk(jwk: { [key: string]: Buffer }, keyType: KeyType): any;

    /**
     * create Key from SPKI
     * @param raw DER data raw
     * @param callback callback function (err: Error, key: Key)
     */
    static importSpki(raw: Buffer, callback: (err: Error, key: Key) => void): void;

    /**
     * create Key from PKCS8
     * @param raw DER data raw
     * @param callback callback function (err: Error, key: KeyPair)
     */
    static importPkcs8(raw: Buffer, callback: (err: Error, key: Key) => void): void;
}

export declare class AesKey {
    /**
     * generate key
     * @param keySize size of generated key (should be 16, 24, 32)
     * @param callback callback function (err: Error, key: KeyPair)
     */
    static generate(keySize: number, callback: (err: Error, key: AesKey) => void): void;
    encrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
    encryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
    decrypt(cipher: string, iv: Buffer, input: Buffer, callback: (err: Error, data: Buffer) => void): void;
    decryptGcm(iv: Buffer, input: Buffer, aad: Buffer | undefined, tag: number, callback: (err: Error, data: Buffer) => void): void;
    export(callback: (err: Error, raw: Buffer) => void): void;
    static import(raw: Buffer, callback: (err: Error, key: AesKey) => void): void;
    wrapKey(data: Buffer, callback: (err: Error, data: Buffer) => void): void;
    unwrapKey(data: Buffer, callback: (err: Error, data: Buffer) => void): void;
}

export declare class HmacKey {
    /**
     * generate key
     * @param keySize size of generated key (should be 16, 24, 32)
     * @param callback callback function (err: Error, key: KeyPair)
     */
    static generate(keySize: number, callback: (err: Error, key: AesKey) => void): void;

    export(callback: (err: Error, raw: Buffer) => void): void;
    static import(raw: Buffer, callback: (err: Error, key: AesKey) => void): void;
    /**
     * sign data
     * @param digestName name of digest algorithm
     * @param message message
     * @param callback callback function (err: Error, signature: Buffer)
     */
    sign(digestName: string, message: Buffer, callback: (err: Error, signature: Buffer) => void): void;

    /**
     * verify data
     * @param digestName name of digest algorithm
     * @param message message
     * @param signature signature from message
     * @param callback callback function (err: Error, valid: boolean)
     */
    verify(digestName: string, message: Buffer, signature: Buffer, callback: (err: Error, valid: boolean) => void): void;
}


/**
 * PKKDF2 crypto key
 * 
 * @export
 * @class Pbkdf2Key
 */
export declare class Pbkdf2Key {

    /**
     * Creates Pbkdf2Key from raw
     * 
     * @static
     * @param {Buffer} raw Raw of data
     * @param {(error: Error, data: Pbkdf2Key) => void} cb
     * 
     * @memberOf Pbkdf2Key
     */
    static importKey(raw: Buffer, cb: (error: Error, data: Pbkdf2Key) => void): void;

    /**
     * Derives bits
     * 
     * @param {string} digestName   SHA digest name. SHA-1, SHA-256, SHA-384, SHA-512
     * @param {number} salt         Salt
     * @param {number} iterations   Iterations
     * @param {number} bitsLength   Size of derived buffer in bits
     * @param {(error: Error, data: Buffer) => void} cb Callback
     * 
     * @memberOf Pbkdf2Key
     */
    public deriveBits(digestName: string, salt: Buffer, iterations: number, bitsLength: number, cb: (error: Error, data: Buffer) => void): void;
}

export declare class Core {
    /**
     * Returns a digest generated from the hash function and text given as parameters
     * @param {string} digst function name
     * @param {Buffer} message for hash generation
     * @param {Function} callback function (err: Error, digest: Buffer)
     */
    static digest(digestName: string, messgae: Buffer, callback: (err: Error, digest: Buffer) => void): void;
}

module.exports = native;