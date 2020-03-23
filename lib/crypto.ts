// Core
import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";
import * as core from "webcrypto-core";

// Local
import { CryptoKeyStorage } from "./key_storage";
import { SubtleCrypto } from "./subtle";

export interface CryptoOptions {
  directory?: string;
}

/**
 * OpenSSL with WebCrypto Interface
 */
export class Crypto extends core.Crypto {

  public keyStorage: CryptoKeyStorage;

  public subtle = new SubtleCrypto();
  /**
   * Constructor
   */
  constructor(options?: CryptoOptions) {
    super();

    this.keyStorage = new CryptoKeyStorage(this, options?.directory ?? path.join(os.homedir(), ".node-webcrypto-ossl"));
  }

  /**
   * Generates cryptographically random values
   * @param array Initialize array
   */
  // Based on: https://github.com/KenanY/get-random-values
  public getRandomValues<T extends ArrayBufferView>(array: T): T {
    if (ArrayBuffer.isView(array)) {
      if (array.byteLength > 65536) {
        throw new core.OperationError(`Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (${array.byteLength}) exceeds the number of bytes of entropy available via this API (65536).`);
      }
      const bytes = crypto.randomBytes(array.byteLength);
      (array as any).set(new (array.constructor as typeof Uint8Array)(bytes.buffer));
      return array;
    } else {
      throw new core.OperationError(`Failed to execute 'getRandomValues' on 'Crypto': Expected ArrayBufferView for 'array' argument.`);
    }
  }

}
