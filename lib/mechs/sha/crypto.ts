import * as native from "native";
import * as core from "webcrypto-core";

export class ShaCrypto {

  /**
   * Returns size of the hash algorithm in bits
   * @param algorithm Hash algorithm
   * @throws Throws Error if an unrecognized name
   */
  public static size(algorithm: Algorithm) {
    switch (algorithm.name.toUpperCase()) {
      case "SHA-1":
        return 160;
      case "SHA-256":
        return 256;
      case "SHA-384":
        return 384;
      case "SHA-512":
        return 512;
      default:
        throw new Error("Unrecognized name");
    }
  }

  public static digest(algorithm: Algorithm, data: ArrayBuffer) {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const algName = algorithm.name.toLowerCase();
      switch (algName) {
        case "sha-1":
        case "sha-256":
        case "sha-384":
        case "sha-512":
          native.Core.digest(algName.replace("-", ""), Buffer.from(data), (err, digest) => {
            if (err) {
              reject(err);
            } else {
              resolve(digest.buffer);
            }
          });
          break;
        default:
          throw new core.AlgorithmError("Unsupported algorithm");
      }
    });
  }

}
