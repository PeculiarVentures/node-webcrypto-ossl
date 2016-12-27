# node-webcrypto-ossl

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-ossl/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/node-webcrypto-ossl.svg?branch=master)](https://travis-ci.org/PeculiarVentures/node-webcrypto-ossl)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/node-webcrypto-ossl/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/node-webcrypto-ossl?branch=master)
[![NPM version](https://badge.fury.io/js/node-webcrypto-ossl.png)](http://badge.fury.io/js/node-webcrypto-ossl)

[![NPM](https://nodei.co/npm-dl/node-webcrypto-ossl.png?months=2&height=2)](https://nodei.co/npm/node-webcrypto-ossl/)

We wanted to be able to write Javascript that used crypto on both the client and the server but we did not want to rely on Javascript implementations of crypto. The only native cryptography availible in browser is [Web Crypto](caniuse.com/#search=cryptography), this resulted in us creating a `node-webcrypto-ossl` a native polyfil for WebCrypto based on Openssl.

## Table Of Contents

* [WARNING](#warning)
* [Installing](#installing)
  * [Clone Repo](#clone-repo)
  * [Install Dependencies](#install-dependencies)
  * [Install](#install)
  * [Test](#test)
* [Threat Model](#threat-model)
  * [Assumptions](#assumptions)
  * [Threats From Weak Cryptography](#threats-from-weak-cryptography)
  * [Threats From Improper Use Of Cryptography](#threats-from-improper-use-of-cryptography)
* [Bug Reporting](#bug-reporting)
* [Related](#related)

## WARNING

**At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.**

## Installation

### Clone Repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-ossl
cd node-webcrypto-ossl
```

### Install 

```                          
npm install
```

### Test

```
mocha
```

## Supported algorithms

| Algorithm name    | generateKey | digest  | export/import | sign/verify | encrypt/decrypt | wrapKey/unwrapKey | derive  |
|-------------------|-------------|---------|---------------|-------------|-----------------|-------------------|---------|
| SHA-1             |             |    X    |               |             |                 |                   |         |
| SHA-256           |             |    X    |               |             |                 |                   |         |
| SHA-384           |             |    X    |               |             |                 |                   |         |
| SHA-512           |             |    X    |               |             |                 |                   |         |
| RSASSA-PKCS1-v1_5 |      X      |         |       X       |      X      |                 |                   |         |
| RSA-PSS           |      X      |         |       X       |      X      |                 |                   |         |
| RSA-OAEP          |      X      |         |       X       |             |        X        |         X         |         |
| AES-CBC           |      X      |         |       X       |             |        X        |         X         |         |
| AES-GCM           |      X      |         |       X       |             |        X        |         X         |         |
| AES-KW            |      X      |         |       X       |             |                 |         X         |         |
| ECDSA             |      X      |         |       X       |      X      |                 |                   |         |
| ECDH              |      X      |         |       X       |             |                 |                   |    X    |
| HMAC              |      X      |         |       X       |      X      |                 |                   |         |
| PBKDF2            |             |         |       X       |             |                 |                   |    X    |

## KeyStorage

To use KeyStorage you shoud init WebCrypto with `directory` option. If `directory` option is missing then `keyStorage` is `null`

```javascript
var WebCrypto = require("node-webcrypto-ossl");

var webcrypto = new WebCrypto({
  directory: "key_storage"
})
```

KeyStorage implements interface of [W3 Storage](https://developer.mozilla.org/en-US/docs/Web/API/Storage)

```javascript
var keyStorage = webcrypto.keyStorage;

// generating RSA key
webcrypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 1024,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: {
      name: "SHA-1"
    }
  },
    false,
    ["sign", "verify"]
  )
  .then(function(keyPairs){
    /** 
     * saving private RSA key to KeyStorage
     * creates file ./key_storage/prvRSA-1024.json
     */
    keyStorage.setItem("prvRSA-1024", keyPairs.privateKey);
  })
```

To get key from KeyStorage
```javascript
var rsaKey = webcrypto.getItem("prvRSA-1024");
```

## Threat Model

The threat model is defined in terms of what each possible attacker can achieve. 

### Assumptions

TODO: ADD ASSUMPTIONS

### Threats From A node-webcrypto-ossl Defect

TODO: ADD THREATS FROM NODE-WEBCRYPTO-OSSL DEFECT

### Threats From Weak Cryptography

TODO: ADD THREATS FROM WEAK CRYPTOGRAPHY

### Threats From Improper Use Of Cryptography

TODO: ADD THREATS FOR IMPROPER USE OF CRYPTOGRAPHY


## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. node-webcrypto-ossl has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.


## Related
 - [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
 - [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
 - [OpenSSL](https://github.com/openssl/openssl)
 - [OpenSSL AES GCM encrypt/decrypt](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
