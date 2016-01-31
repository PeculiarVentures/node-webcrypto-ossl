import * as iwc from "./iwebcrypto";
import * as subtle from "./subtle";
import * as crypto from "crypto";

/**
 * PKCS11 with WebCrypto Interface
 */
export default class WebCrypto implements iwc.IWebCrypto {


    public subtle: iwc.ISubtleCrypto = null;

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    getRandomValues(array): any {
        return crypto.randomBytes(array.byteLength);
    }

    /**
     * Constructor
     */
    constructor() {
        this.subtle = new subtle.SubtleCrypto();
    }
}