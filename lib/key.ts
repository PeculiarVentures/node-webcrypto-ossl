import * as native from "./native";

export class CryptoKey implements NodeCryptoKey {
    type: string;
    extractable: boolean;
    algorithm: NodeAlgorithm;
    usages: string[] = [];

    private native_: any;
    get native(): any{
        return this.native_;
    }

    constructor(key: native.AesKey, alg: NodeAlgorithm, type: string, extractable: boolean, keyUsages: string[]);
    constructor(key: native.Key, alg: NodeAlgorithm, type: string, extractable: boolean, keyUsages: string[]);
    constructor(key: native.AesKey | native.Key, alg: NodeAlgorithm, type: string, extractable: boolean, keyUsages: string[]) {
        this.native_ = key;

        this.extractable = extractable;
        this.algorithm = alg;
        // set key type
        this.type = type;
        // set key usages
        this.usages = keyUsages;
    }
}