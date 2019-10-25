// TODO:
// - Node's default Buffer or buffer-safe
// - Node's default crypto.pbkdf2 or pbkdf2 as additional dependency (official)
// - Node's default chacha20-poly1305 or https://github.com/calvinmetcalf/chacha20poly1305 (non-official)

const pbkdf2 = require("pbkdf2");
const chacha = require('chacha');

const PBKDF_ITERATIONS = 19162;
const SALT_SIZE = 32;
const KEY_SIZE = 32;
const DIGEST = 'sha512';
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const CIPHER = 'chacha20-poly1305';

const promisifyPbkdf2 = (password, salt) => {
  return new Promise((resolve, reject) => {
    pbkdf2.pbkdf2(password, salt, PBKDF_ITERATIONS , KEY_SIZE, DIGEST, (err, key) => {
      if (err) return reject(err);
      resolve(key);
    })
  })
}

const encryptWithPassword = async (
  passwordHex,
  saltHex,
  nonceHex,
  dataHex,
) => {
  // convert hex strings into byte arrays (buffers)
  const password = Buffer.from(passwordHex, 'hex');
  const salt = Buffer.from(saltHex, 'hex');
  const nonce = Buffer.from(nonceHex, 'hex');
  const aad = Buffer.from('', 'hex');

  if (salt.length != SALT_SIZE) throw new Error('salt length must be 32 bytes');
  if (nonce.length != NONCE_SIZE) throw new Error('nonce length must be 12 bytes');

  const key = await promisifyPbkdf2(password, salt);

  // TODO: 'chacha20-poly1305' is only available in node v11.2.0+
  // consider replacing by https://github.com/calvinmetcalf/chacha20poly1305
  // const cipher = crypto.createCipheriv(CIPHER, key, nonce, {
  //   authTagLength: TAG_SIZE,
  // });
  const cipher = chacha.createCipher(key, nonce);

  // cipher.setAAD(aad, { plaintextLength: dataHex.length });
  cipher.setAAD(aad);
  const head = cipher.update(dataHex);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([salt, nonce, tag, head, final]);
  return ciphertext.toString('hex');
}

const decryptWithPassword = async (passwordHex, ciphertextHex) => {
  const password = Buffer.from(passwordHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');
  const salt = ciphertext.slice(0, SALT_SIZE);
  const nonce = ciphertext.slice(SALT_SIZE, SALT_SIZE + NONCE_SIZE);
  const tag = ciphertext.slice(SALT_SIZE + NONCE_SIZE, SALT_SIZE + NONCE_SIZE + TAG_SIZE);
  const cipherdata = ciphertext.slice(SALT_SIZE + NONCE_SIZE + TAG_SIZE);
  const aad = Buffer.from('', 'hex');
  const key = await promisifyPbkdf2(password, salt);

  // const decipher = crypto.createDecipheriv(CIPHER, key, nonce, {
  //   authTagLength: TAG_SIZE,
  // });
  const decipher =  chacha.createDecipher(key, nonce);

  decipher.setAuthTag(tag); // tag must be buffer
  decipher.setAAD(aad); // aad must be buffer
  let decrypted = decipher.update(cipherdata);
  decrypted += decipher.final();
  return decrypted;
}

exports.encryptWithPassword = encryptWithPassword;
exports.decryptWithPassword = decryptWithPassword;
