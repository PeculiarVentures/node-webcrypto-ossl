import * as native from "./native";

export interface CryptoKeyPair extends NativeCryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export type NativeKey = native.AesKey | native.Key | native.Pbkdf2Key | native.HmacKey;

export class CryptoKey implements NativeCryptoKey {
    type: string;
    extractable: boolean;
    algorithm: Algorithm;
    usages: string[] = [];

    private native_: NativeKey;
    get native() {
        return this.native_;
    }

    constructor(key: NativeKey, alg: Algorithm, type: string, extractable: boolean, keyUsages: string[]) {
        this.native_ = key;

        this.extractable = extractable;
        this.algorithm = alg;
        // set key type
        this.type = type;
        // set key usages
        this.usages = keyUsages;
    }
}