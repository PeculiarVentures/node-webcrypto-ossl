import * as native from "./native";

export interface CryptoKeyPair extends NativeCryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export class CryptoKey implements NativeCryptoKey {
    type: string;
    extractable: boolean;
    algorithm: Algorithm;
    usages: string[] = [];

    private native_: native.AesKey | native.Key;
    get native(): native.AesKey | native.Key | native.HmacKey {
        return this.native_;
    }

    constructor(key: native.AesKey | native.Key, alg: Algorithm, type: string, extractable: boolean, keyUsages: string[]) {
        this.native_ = key;

        this.extractable = extractable;
        this.algorithm = alg;
        // set key type
        this.type = type;
        // set key usages
        this.usages = keyUsages;
    }
}