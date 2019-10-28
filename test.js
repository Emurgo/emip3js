const emip3 = require('.');

test('valid encryption and decryption', async () => {
  const password = 'password';
  const passwordHex = Buffer.from(password, 'utf8').toString('hex');
  const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3'; // 32B
  const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12B
  const data = 'some data to encrypt';
  const dataHex = Buffer.from(data, 'utf8').toString('hex');
  const ciphertext = await emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
  const decryptedDataHex = await emip3.decryptWithPassword(passwordHex, ciphertext);
  expect(decryptedDataHex).toBe(dataHex);
});

describe('invalid encryption', () => {
  const passwordHex = Buffer.from('password', 'utf8').toString('hex');
  const dataHex = Buffer.from('some data to encrypt', 'utf8').toString('hex');

  it('should throw on invalid salt', async () => {
    const saltHex = '50515253';
    const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12B
    const promise = emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
    await expect(promise).rejects.toThrow();
  });

  it('should throw on invalid nonce', async () => {
    const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1';
    const nonceHex = 'invalid nonce';
    const promise = emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
    await expect(promise).rejects.toThrow();
  });

});

describe('invalid decryption', () => {
  const passwordHex = Buffer.from('password', 'utf8').toString('hex');
  const dataHex = Buffer.from('some data to encrypt', 'utf8').toString('hex');
  const saltHex = '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3'; // 32B
  const nonceHex = '50515253c0c1c2c3c4c5c6c7'; // 12B

  it('should throw on invalid password', async () => {
    const ciphertext = await emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
    const wrongPassword = 'wrongPassword';
    const promise = emip3.decryptWithPassword(wrongPassword, saltHex, nonceHex, ciphertext);
    await expect(promise).rejects.toThrow();
  });

  it('should throw on corrupted cyphertext', async () => {
    const ciphertext = await emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
    const corruptedCiphertext = ciphertext.slice(0, ciphertext.length - 1);
    const promise = emip3.decryptWithPassword(passwordHex, saltHex, nonceHex, corruptedCiphertext);
    await expect(promise).rejects.toThrow();
  });

  it('should throw on insufficient input', async () => {
    const ciphertext = await emip3.encryptWithPassword(passwordHex, saltHex, nonceHex, dataHex);
    const corruptedCiphertext = ciphertext.slice(0, 32 + 12 + 16); // includes only metadata
    const promise = emip3.decryptWithPassword(passwordHex, saltHex, nonceHex, corruptedCiphertext);
    await expect(promise).rejects.toThrow(new Error('not enough data to decrypt'));
  });

});
