# emip3js

emip3js is a javascript implementation of [EmIP-003](https://github.com/Emurgo/EmIPs/blob/master/specs/emip-003.md).

## Usage

### Encryption
```js
const password = 'password';
const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3'; // 32-byte hex string
const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12-byte hex string
const data = 'some data to encrypt';
const dataHex = Buffer.from(data, 'utf8').toString('hex');

const ciphertext = await encryptWithPassword(password, saltHex, nonceHex, dataHex);
```

### Decryption
```js
const decryptedDataHex = await emip3.decryptWithPassword(password, ciphertext);
```
