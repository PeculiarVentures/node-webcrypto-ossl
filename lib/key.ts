import * as iwc from "./iwebcrypto";

export class CryptoKey implements iwc.ICryptoKey {
    type: string;
    extractable: boolean;
    algorithm: any;
    usages: string[] = [];

    private _key;
    get key(): any {
        return this._key;
    }

    constructor(key, alg: iwc.IAlgorithmIdentifier, type: string) {
        this._key = key;
        this.extractable = true;
        this.algorithm = alg;
        // set key type
        this.type = type;
        // set key usages
        this.usages = [];
    }
}

