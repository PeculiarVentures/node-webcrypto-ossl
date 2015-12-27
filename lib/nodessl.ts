import * as key from "./native_key";

export namespace nodessl {
    export let KeyType = key.KeyType;
    export let Key = key.KeyPair;
    export let sign = key.sign;
    export let verify = key.verify;
} 