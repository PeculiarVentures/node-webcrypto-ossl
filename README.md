# node-webcrypto-ossl

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-ossl/master/LICENSE)

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

### Install Dependencies

```
npm install node-gyp -g
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

### Install 

```                          
npm install
```

### Test

```
mocha
```

## Threat Model

The threat model is defined in terms of what each possible attacker can achieve. 

### Assumptions

TODO: ADD ASSUMPTIONS

### Threats From A node-webcrypto-ossl Defect

TODO: ADD THREATS FROM HANCOCK SERVICE COMPROMISE

### Threats From Weak Cryptography

TODO: ADD THREATS FROM WEAK CRYPTOGRAPHY

### Threats From Improper Use Of Cryptography

TODO: ADD THREATS FOR IMPROPER USE OF CRYPTOGRAPHY


## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. node-webcrypto-ossl has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.


## Related
 - [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [OpenSSL](https://github.com/openssl/openssl)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
 - [OpenSSL AES GCM encrypt/decrypt](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
