// TODO:
// - Node's default Buffer or buffer-safe
// - Node's default crypto.pbkdf2 or pbkdf2 as additional dependency (official)
// - Node's default chacha20-poly1305 or https://github.com/calvinmetcalf/chacha20poly1305 (non-official)

const crypto = require('crypto');
// TODO: remove this dependency (?)
// var pbkdf2 = require('pbkdf2');

const PBKDF_ITERATIONS = 19162;
const SALT_SIZE = 32;
const KEY_SIZE = 32;
const DIGEST = 'sha512';
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const CIPHER = 'chacha20-poly1305';

const promisifyPbkdf2 = (password, salt) => {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, PBKDF_ITERATIONS , KEY_SIZE, DIGEST, (err, key) => {
      if (err) return reject(err);
      resolve(key);
    })
  })
}

const encryptWithPassword = async (
  password,
  saltHex,
  nonceHex,
  dataHex,
) => {
  const key = await promisifyPbkdf2(password, saltHex);
  const salt = Buffer.from(saltHex, 'hex');
  const nonce = Buffer.from(nonceHex, 'hex');
  const aad = Buffer.from('', 'hex');

  if (salt.length != SALT_SIZE) throw new Error('salt length must be 32 bytes');
  if (nonce.length != NONCE_SIZE) throw new Error('nonce length must be 12 bytes');

  // TODO: 'chacha20-poly1305' is only available in node v11.2.0+
  // consider replacing by https://github.com/calvinmetcalf/chacha20poly1305
  const cipher = crypto.createCipheriv(CIPHER, key, nonce, {
    authTagLength: TAG_SIZE,
  });
  cipher.setAAD(aad, { plaintextLength: dataHex.length });
  const head = cipher.update(dataHex);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([salt, nonce, tag, head, final]);
  return ciphertext.toString('hex');
}

const decryptWithPassword = async (password, ciphertext) => {
  const ciphertextBytes = Buffer.from(ciphertext, 'hex');
  const salt = ciphertextBytes.slice(0, SALT_SIZE);
  const nonce = ciphertextBytes.slice(SALT_SIZE, SALT_SIZE + NONCE_SIZE);
  const tag = ciphertextBytes.slice(SALT_SIZE + NONCE_SIZE, SALT_SIZE + NONCE_SIZE + TAG_SIZE);
  const aad = Buffer.from('', 'hex');
  const cipherdata = ciphertextBytes.slice(SALT_SIZE + NONCE_SIZE + TAG_SIZE);
  const key = await promisifyPbkdf2(password, salt.toString('hex'));
  const decipher = crypto.createDecipheriv(CIPHER, key, nonce, {
    authTagLength: TAG_SIZE,
  });
  decipher.setAuthTag(tag); // tag must be buffer
  decipher.setAAD(aad); // aad must be buffer
  let decrypted = decipher.update(cipherdata);
  decrypted += decipher.final();
  return decrypted;
}

exports.encryptWithPassword = encryptWithPassword;
exports.decryptWithPassword = decryptWithPassword;
