# node-webcrypto-ossl
A WebCrypto Polyfill for Node in typescript built on OpenSSL

# Install instructions

## Clone Repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-ossl
cd node-webcrypto-ossl
```

## Install Global Dependencies
- node-gyp (node native module compiler)
- typescript (TypeScript compiler)
- tsd (TypeScript Defenition compiler)
- mocha (test)

```
npm install node-gyp -g
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

## Install & Compile 

```
npm install
tsd install
tsc
node-gyp configure build
```

* If you experience any errors make sure you have downloaded TypeScript dependencies


# Test

```
mocha
```

### Related
 - [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [OpenSSL](https://github.com/openssl/openssl)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
