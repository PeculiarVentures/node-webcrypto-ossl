// Core
import * as fs from "fs";
import * as mkdirp from "mkdirp";
import * as path from "path";
import * as core from "webcrypto-core";

import { CryptoKey } from "./key";
import * as native from "./native";

const JSON_FILE_EXT = ".json";

class KeyStorageError extends core.WebCryptoError { }

export interface IKeyStorageItem extends NativeCryptoKey {
    name: string;
    keyJwk: any;
    file?: string;
}

function jwkBufferToBase64(jwk: IKeyStorageItem): IKeyStorageItem {
    const cpyJwk = jwk.keyJwk as any;

    for (const i in cpyJwk) {
        const attr = cpyJwk[i];
        if (Buffer.isBuffer(attr)) {
            cpyJwk[i] = attr.toString("base64");
        }
    }

    return jwk;
}

function jwkBase64ToBuffer(jwk: IKeyStorageItem): IKeyStorageItem {
    const cpyJwk = jwk.keyJwk as any;

    const reserved = ["kty", "usage", "alg", "crv", "ext", "alg", "name"];

    for (const i in cpyJwk) {
        const attr = cpyJwk[i];
        if (reserved.indexOf(i) === -1 && typeof attr === "string") {
            try {
                const buf = Buffer.from(attr, "base64");
                cpyJwk[i] = buf;
            } catch (e) {
                // console.log(e);
            }
        }
    }

    return jwk;
}

/**
 * Manage keys in folder
 *
 * @export
 * @class KeyStorage
 */
export class KeyStorage {

    protected directory: string = "";
    protected keys: { [key: string]: IKeyStorageItem } = {};

    /**
     * Creates an instance of KeyStorage.
     *
     * @param {string} directory Path to directory
     */
    constructor(directory: string) {
        this.directory = directory;

        if (!fs.existsSync(directory)) {
            this.createDirectory(directory);
        }

        this.readDirectory();
    }

    /**
     * Clears KeyStorage
     * - be careful, removes all files from selected directory
     */
    public clear(): void {
        if (!this.directory) {
            return;
        }
        this.keys = {}; // clear keys
        const items = fs.readdirSync(this.directory);
        items.forEach((item) => {
            if (item !== "." && item !== "..") {
                const file = path.join(this.directory, item);
                const stat = fs.statSync(file);
                if (stat.isFile()) {
                    fs.unlinkSync(file);
                }
            }
        });
    }

    /**
     * Returns a CryptoKey from storage by name
     *
     * @param {string} key Name of
     * @returns {CryptoKey}
     */
    public getItem(key: string): CryptoKey | null {
        let item = this.getItemById(key);
        if (!item) {
            return null;
        }

        item = jwkBase64ToBuffer(item);
        let res: CryptoKey;
        let nativeKey: native.Key;
        switch (item.type.toLowerCase()) {
            case "public":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PUBLIC);
                break;
            case "private":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
            default:
                throw new Error(`Unknown type '${item.type}'`);
        }
        res = new CryptoKey(nativeKey, item.algorithm as any, item.type, item.extractable, item.usages);
        return res;
    }

    public key(index: number): string {
        throw new Error("Not implemented yet");
    }

    /**
     * Removes key from Storage
     *
     * @param {string} key Name of key in Storage
     */
    public removeItem(key: string): void {
        const item = this.getItemById(key);
        if (item) {
            this.removeFile(item);
            delete this.keys[key];
        }
    }

    public setItem(key: string, data: CryptoKey): void {
        const nativeKey = (data as CryptoKey).native;
        let jwk: any = null;
        switch (data.type.toLowerCase()) {
            case "public":
                jwk = (nativeKey as native.Key).exportJwk(native.KeyType.PUBLIC);
                break;
            case "private":
                jwk = (nativeKey as native.Key).exportJwk(native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
            default:
                throw new Error(`Unsupported key type '${data.type}'`);
        }
        if (jwk) {
            let item: IKeyStorageItem = {
                algorithm: data.algorithm,
                usages: data.usages,
                type: data.type,
                keyJwk: jwk,
                name: key,
                extractable: data.extractable,
            };
            item = jwkBufferToBase64(item);
            this.saveFile(item);
            this.keys[key] = item;
        }
    }

    protected createDirectory(directory: string, flags?: any) {
        mkdirp.sync(directory, flags);
    }

    /**
     * Read JWK file.
     * If file doesn't have IKeyStorageItem data returns Null
     *
     * @protected
     * @param {string} file Path to file
     * @returns {IKeyStorageItem}
     */
    protected readFile(file: string): IKeyStorageItem | null {
        if (!fs.existsSync(file)) {
            throw new KeyStorageError(`File '${file}' is not exists`);
        }
        const fText = fs.readFileSync(file, "utf8");
        let json: IKeyStorageItem;
        try {
            json = JSON.parse(fText);
        } catch (e) {
            return null;
        }
        // Add info about file
        json.file = file;

        // check JSON structure
        if (json.algorithm && json.type && json.usages && json.name) {
            return json;
        }
        return null;
    }

    /**
     * Read all files from folder and push Keys to internal field "keys"
     *
     * @protected
     */
    protected readDirectory() {
        if (!this.directory) {
            throw new KeyStorageError("KeyStorage directory is not set");
        }
        this.keys = {}; // clear keys
        const items = fs.readdirSync(this.directory);
        items.forEach((item) => {
            if (item !== "." && item !== "..") {
                const file = path.join(this.directory, item);
                const stat = fs.statSync(file);
                if (stat.isFile()) {
                    const key = this.readFile(file);
                    if (key) {
                        this.keys[key.name] = key;
                    }
                }
            }
        });
    }

    /**
     * Save file to directory
     *
     * @protected
     * @param {IKeyStorageItem} key
     */
    protected saveFile(key: IKeyStorageItem) {
        const json = JSON.stringify(key);
        fs.writeFileSync(path.join(this.directory, key.name + JSON_FILE_EXT), json, {
            encoding: "utf8",
            flag: "w",
        });
    }

    protected removeFile(key: IKeyStorageItem) {
        let file = key.file;
        if (!file) {
            file = path.join(this.directory, key.name + JSON_FILE_EXT);
        }
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
        }
    }

    /**
     * Returns amount fo key in storage
     *
     * @readonly
     * @type {number}
     */
    get length(): number {
        return Object.keys(this.keys).length;
    }

    protected getItemById(id: string): IKeyStorageItem {
        return this.keys[id] || null;
    }

}
