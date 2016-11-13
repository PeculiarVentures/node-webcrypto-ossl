// Core
import * as webcrypto from "webcrypto-core";

// Local
import * as subtle from "./subtle";
import * as crypto from "crypto";
import {KeyStorage} from "./key_storage";

// Fix btoa and atob for NodeJS
let _global = global as any;
_global.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
_global.atob = (data: string) => new Buffer(data, "base64").toString("binary");


const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";

export interface WebCryptoOptions {
    directory?: string;
}

/**
 * OpenSSL with WebCrypto Interface
 */
class WebCrypto implements NativeCrypto  {

    keyStorage: KeyStorage;

    subtle: SubtleCrypto;

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    getRandomValues(array: NodeBufferSource): NodeBufferSource;
    getRandomValues(array: ArrayBufferView): ArrayBufferView;
    getRandomValues(array: NodeBufferSource): NodeBufferSource {
        if (array.byteLength > 65536) {
            let error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
            error.code = 22;
            throw error;
        }
        let bytes = crypto.randomBytes(array.byteLength);
        (array as Uint8Array).set(bytes);
        return array;
    }

    /**
     * Constructor
     */
    constructor(options?: WebCryptoOptions) {
        this.subtle = new subtle.SubtleCrypto();
        if (options && options.directory)
            this.keyStorage = new KeyStorage(options.directory);
    }
}
module.exports = WebCrypto;