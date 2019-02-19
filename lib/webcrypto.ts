// Core
import * as crypto from "crypto";
import * as webcrypto from "webcrypto-core";

// Local
import { KeyStorage } from "./key_storage";
import * as subtle from "./subtle";

const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";
const ERR_RANDOM_NO_VALUE = "Failed to execute 'getRandomValues' on 'Crypto': Expected ArrayBufferView but got %s.";

export interface WebCryptoOptions {
    directory?: string;
}

/**
 * OpenSSL with WebCrypto Interface
 */
class WebCrypto implements NativeCrypto {

    public keyStorage: KeyStorage;

    public subtle: SubtleCrypto;

    /**
     * Constructor
     */
    constructor(options?: WebCryptoOptions) {
        this.subtle = new subtle.SubtleCrypto();
        if (options && options.directory) {
            this.keyStorage = new KeyStorage(options.directory);
        }
    }

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    public getRandomValues<T extends Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null>(array: T): T {
        if (array) {
            if (array.byteLength > 65536) {
                const error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
                error.code = 22;
                throw error;
            }
            const bytes = crypto.randomBytes(array.byteLength);
            (array as Uint8Array).set(new (array.constructor as typeof Uint8Array)(bytes.buffer));
            return array;
        } else {
            throw new webcrypto.WebCryptoError(ERR_RANDOM_NO_VALUE, array);
        }
    }

}

module.exports = WebCrypto;
