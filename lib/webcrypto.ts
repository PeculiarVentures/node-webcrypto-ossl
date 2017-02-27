// Core
import * as crypto from "crypto";
import * as webcrypto from "webcrypto-core";

// Local
import { KeyStorage } from "./key_storage";
import * as subtle from "./subtle";

// Fix btoa and atob for NodeJS
const g = global as any;
g.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
g.atob = (data: string) => new Buffer(data, "base64").toString("binary");

const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";

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
    public getRandomValues(array: NodeBufferSource): NodeBufferSource;
    public getRandomValues(array: ArrayBufferView): ArrayBufferView;
    public getRandomValues(array: NodeBufferSource): NodeBufferSource {
        if (array.byteLength > 65536) {
            const error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
            error.code = 22;
            throw error;
        }
        const bytes = crypto.randomBytes(array.byteLength);
        (array as Uint8Array).set(new (<typeof Uint8Array>array.constructor)(bytes.buffer));
        return array;
    }

}

module.exports = WebCrypto;
