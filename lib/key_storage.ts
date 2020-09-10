// Core
import * as fs from "fs";
import * as mkdirp from "mkdirp";
import * as path from "path";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Crypto } from "./crypto";

const FILE_EXT = ".jkey";
export interface IKeyStorageItem extends core.NativeCryptoKey {
  jwk: JsonWebKey;
}

/**
 * Manage keys in folder
 */
export class CryptoKeyStorage implements core.CryptoKeyStorage {

  public directory = "";
  public crypto: Crypto;
  private items = new WeakMap<globalThis.CryptoKey, string>();

  public constructor(crypto: Crypto, directory: string) {
    this.crypto = crypto;
    this.directory = path.normalize(directory);
    if (!fs.existsSync(this.directory)) {
      mkdirp.sync(this.directory);
    }
  }

  public getItem(index: string): Promise<globalThis.CryptoKey>;
  public getItem(index: string, algorithm: core.ImportAlgorithms, extractable: boolean, keyUsages: KeyUsage[]): Promise<globalThis.CryptoKey>;
  public async getItem(index: any, algorithm?: any, extractable?: any, keyUsages?: any) {
    const fileKey = this.readFile(this.getFilePath(index));
    if (!fileKey) {
      throw new core.OperationError("Cannot get key form file");
    }
    return this.crypto.subtle.importKey(
      "jwk",
      fileKey.jwk,
      algorithm ?? fileKey.algorithm,
      extractable ?? fileKey.extractable,
      keyUsages ?? fileKey.usages);
  }

  public async keys(): Promise<string[]> {
    const items = fs.readdirSync(this.directory);
    const res: string[] = [];
    items.forEach((item) => {
      if (item !== "." && item !== "..") {
        const file = path.join(this.directory, item);
        const stat = fs.statSync(file);
        if (stat.isFile()) {
          const key = this.readFile(file);
          if (key) {
            res.push(path.parse(item).name);
          }
        }
      }
    });
    return res;
  }

  public async indexOf(item: globalThis.CryptoKey): Promise<string | null> {
    return this.items.get(item) || null;
  }

  public async setItem(item: globalThis.CryptoKey, id?: string): Promise<string> {
    const subtle = this.crypto.subtle as any;
    const provider = subtle.getProvider(item.algorithm.name) as core.ProviderCrypto;
    const jwk = await provider.onExportKey("jwk", item) as JsonWebKey;
    const keyAlgorithm = item.algorithm as any;
    const algorithm: any = { name: keyAlgorithm.name };
    if (keyAlgorithm.hash) {
      // RSA keys
      algorithm.hash = keyAlgorithm.hash;
    }
    const name = id || Convert.ToHex(this.crypto.getRandomValues(new Uint8Array(10)));
    this.writeFile(
      name,
      {
        algorithm,
        extractable: item.extractable,
        usages: item.usages,
        type: item.type,
        jwk,
      });

    // add to weak map
    this.items.set(item, name);

    return name;
  }

  public async hasItem(item: globalThis.CryptoKey): Promise<boolean> {
    return this.items.has(item);
  }

  public async clear(): Promise<void> {
    const keys = await this.keys();
    for (const key of keys) {
      this.removeItem(key);
    }
  }

  public async removeItem(index: string): Promise<void> {
    const fileName = this.getFilePath(index);
    const keyFile = this.readFile(fileName);
    if (keyFile) {
      fs.unlinkSync(fileName);
    }
  }

  private readFile(file: string) {
    const json = fs.readFileSync(file, "utf8");
    let parsedJson: IKeyStorageItem;
    try {
      parsedJson = JSON.parse(json);
    } catch (e) {
      return null;
    }

    // check JSON structure
    if (parsedJson.algorithm && parsedJson.type && parsedJson.usages && parsedJson.jwk) {
      return parsedJson;
    }
    return null;
  }

  private writeFile(name: string, key: IKeyStorageItem) {
    const json = JSON.stringify(key);
    fs.writeFileSync(this.getFilePath(name), json, {
      encoding: "utf8",
      flag: "w",
    });
  }

  private getFilePath(name: string): string {
    return path.join(this.directory, `${name}${FILE_EXT}`);
  }
}
