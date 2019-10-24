const emip3 = require('.');

test('valid encryption and decryption', async () => {
  const password = 'password';
  const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3'; // 32B
  const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12B
  const data = 'some data to encrypt';
  const dataHex = Buffer.from(data, 'utf8').toString('hex');
  const ciphertext = await emip3.encryptWithPassword(password, saltHex, nonceHex, dataHex);
  const decryptedDataHex = await emip3.decryptWithPassword(password, ciphertext);
  expect(decryptedDataHex).toBe(dataHex);
});
