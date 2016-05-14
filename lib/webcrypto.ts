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
    getRandomValues(array: ArrayBufferView): any {
        return crypto.randomBytes(array.byteLength);
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