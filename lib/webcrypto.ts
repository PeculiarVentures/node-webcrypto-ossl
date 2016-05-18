import * as iwc from "./iwebcrypto";
import * as subtle from "./subtle";
import * as crypto from "crypto";
import {KeyStorage} from "./key_storage";

export interface WebCryptoOptions {
    directory: string;
}

/**
 * OpenSSL with WebCrypto Interface
 */
export default class WebCrypto implements iwc.IWebCrypto {

    keyStorage: KeyStorage = null;

    public subtle: iwc.ISubtleCrypto = null;

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    getRandomValues<A extends Int8Array | Uint8Array | Int16Array | Uint16Array | Int32Array | Uint32Array>(typedArray: A): A {
        if (typedArray.byteLength > 65536) {
            let error = new Error();
            (error as any).code = 22;
            error.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
                'ArrayBufferView\'s byte length (' + typedArray.byteLength  + ') exceeds the ' +
                'number of bytes of entropy available via this API (65536).';
            error.name = 'QuotaExceededError';
            throw error;
        }
        let bytes = crypto.randomBytes(typedArray.byteLength);
        typedArray.set(bytes);
        return typedArray;
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