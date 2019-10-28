# emip3js

emip3js is a javascript implementation of [EmIP-003](https://github.com/Emurgo/EmIPs/blob/master/specs/emip-003.md).

## Usage

### Encryption
```js
import {encryptWithPassword, decryptWithPassword} from 'emip3js';

const passwordHex = Buffer.from('password', 'utf8').toString('hex');
const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3'; // 32-byte hex string
const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12-byte hex string
const dataHex = Buffer.from('some data to encrypt', 'utf8').toString('hex');

const ciphertextHex = await encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
```

### Decryption
```js
const decryptedDataHex = await decryptWithPassword(passwordHex, ciphertextHex);
```
