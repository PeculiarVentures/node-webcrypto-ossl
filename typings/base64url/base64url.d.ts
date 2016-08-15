interface IBase64Url {
    /**
     * Encode value to base64url
     * @param {string} value incoming value 
     */
    (value: string): string;
    /**
     * Encode value to base64url
     * @param {Buffer} value incoming value 
     */
    (value: Buffer): string;
    /**
     * Encode value to base64url
     * @param {string} value incoming value 
     */
    encode(value: string): string;
    /**
     * Encode value to base64url
     * @param {Buffer} value incoming value 
     */
    encode(value: Buffer): string;
    /**
     * Convert a base64url encoded string into a raw string.
     * @param b64UrlEncodedString base64url encoded string 
     * @param {string} encoding Encoding defaults to 'utf8'
     */
    decode(b64UrlEncodedString: string, encoding?: string): string;
    /**
     * Convert a base64 encoded string to a base64url encoded string
     * @param {string} b64EncodedString base64 encoded string
     */
    fromBase64(b64EncodedString: string): string;
    /**
     * Convert a base64url encoded string to a base64 encoded string
     * @param b64UrlEncodedString base64url encoded string 
     */
    toBase64(b64UrlEncodedString: string): string;
    /**
     * Convert a base64url encoded string to a base64 encoded string
     * Convert a base64url encoded string to a Buffer
     * @param b64UrlEncodedString base64url encoded string 
     */
    toBuffer(b64UrlEncodedString: string): Buffer;
}

declare module "base64url" {
    export = base64url;
}

declare var base64url: IBase64Url;