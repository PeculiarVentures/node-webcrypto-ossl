# node-webcrypto-ossl
A WebCrypto Polyfill for Node in typescript built on OpenSSL

# Install instruction

## clone repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-ossl
cd node-webcrypto-ossl
```

## set npm global dependencies
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

## install

```
npm install
```

If it has errors you can do next

- download TypeScript dependencies

```
tsd install
```

- compile TypeScript
  
```
tsc
```

- compile native module

```
node-gyp configure build
```

# Test

```
mocha
```

### Related
 - [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [OpenSSL](https://github.com/openssl/openssl)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
