# node-webcrypto-ossl
A WebCrypto Polyfill for Node in TypeScript built on OpenSSL

## Installation

#### Clone Repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-ossl
cd node-webcrypto-ossl
```

#### Install Dependencies
```
npm install node-gyp -g
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

#### Install & Compile 

```
npm install
tsd install
tsc
node-gyp configure build
```

> If you experience any errors make sure you have downloaded TypeScript dependencies


## Tests

```
mocha
```

## Suitability

At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.

## Bug Reporting

Please report bugs either as pull requests or as issues in the issue tracker. node-webcrypto-ossl has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.

## Dependencies
- node-gyp (node native module compiler)
- typescript (TypeScript compiler)
- tsd (TypeScript Defenition compiler)
- mocha (test)
 
## Related
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [OpenSSL](https://github.com/openssl/openssl)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
 - [OpenSSL AES GCM encrypt/decrypt](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
