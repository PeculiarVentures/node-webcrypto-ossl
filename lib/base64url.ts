export class Base64Url {

    static encode(value: Buffer): string;
    static encode(value: string, encoding?: string): string;
    static encode(value: string | Buffer, encoding?: string) {
        let data: Buffer;
        if (!Buffer.isBuffer(value)) {
            data = new Buffer(value, encoding);
        }
        else
            data = value;
        let res = data.toString("base64")
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        return res;
    }

    static decode(base64url: string): Buffer;
    static decode(base64url: string, encoding: string): string;
    static decode(base64url: string, encoding?: string): Buffer | string {
        while (base64url.length % 4) {
            base64url += "=";
        }
        base64url
            .replace(/\-/g, "+")
            .replace(/_/g, "/");
        let buf = new Buffer(base64url, "base64");
        if (encoding)
            return buf.toString(encoding);
        return buf;
    }
}