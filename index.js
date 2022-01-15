const {randomBytes} = require('bcrypto/lib/random');
const aes = require('bcrypto/lib/aes');
const secp256k1 = require('bcrypto/lib/secp256k1');
const sha256 = require('bcrypto/lib/sha256');
const base58 = require('bcrypto/lib/encoding/base58');
const {Address} = require('hsd/lib/primitives');

/****
***
** encrypt()
**   wallet     - Wallet from hsd
**   node       - Node from hsd
**   passphrase - passphrase for wallet
**   name       - my name
**   target     - recipient's name
**   message    - the message to encrypt
**
**   returns {ciphertext,iv}
**     ciphertext - an AES encrypted message
**     iv         - initialization vector for ciphertext
**     or null
***
****/
async function encrypt(wallet, node, passphrase, name, target, message) {
  const keys = await getKeysFromName(wallet, node, passphrase, name);
  const targetPubkey = await getPubkeyFromName(node, target);
  const secret = _ecdh(targetPubkey, keys.privateKey);
  return _encrypt(message, secret);
}

/****
***
** decrypt()
**   wallet     - Wallet from hsd
**   node       - Node from hsd
**   passphrase - passphrase for wallet
**   name       - my name
**   sender     - sender's name
**   ciphertext - the ciphertext
**   iv         - the initialization vector
**
**   returns {ciphertext,iv}
**     string containing the decrypted message
**     or null
***
****/
async function decrypt(wallet, node, passphrase, name, sender, ciphertext, iv) {
  const keys = await getKeysFromName(wallet, node, passphrase, name);
  const senderPubkey = await getPubkeyFromName(node, sender);
  const secret = _ecdh(senderPubkey, keys.privateKey);
  return _decrypt(ciphertext, iv, secret);
}

/*
** handshake functions
*/
async function getPubkeyFromName(node, name) { return await getPubkeyFromAddress(node, await getAddressFromName(node, name)) }
async function getPubkeyFromAddress(node, address) {
  let result = await node.getTXByAddress(address);
  for(let x=0;x<result.length;x++)
    for(let y=0;y<result[x].inputs.length;y++)
      if(result[x].inputs[y].coin.address===address) return result[x].inputs[y].witness[1];
  return null;
}
async function getAddressFromName(node, name) {
  let result = await node.execute('getnameinfo', [name]);
  if(!result || !result.info || !result.info.owner || !result.info.owner.hash) return null;
  result = await node.getCoin(result.info.owner.hash, result.info.owner.index);
  if(!result || !result.address) return null;
  return result.address;
}
async function getKeysFromName(wallet, node, passphrase, name) {
  let me, privWIF, privkey58, privkey, pubkey, _tmp;
  me = await getAddressFromName(node, name);
  privWIF = (await wallet.getWIF(me, passphrase)).privateKey;
  privkey58 = base58.decode(privWIF).slice(1);      // remove first byte
  _tmp = new Buffer.alloc(privkey58.length - 5);    // remove last 4 bytes and compression byte
  privkey58.copy(_tmp, 0, 0, privkey58.length - 5);
  privkey58=_tmp;
  pubkey = secp256k1.publicKeyCreate(privkey58, true).toString('hex');
  privkey = privkey58.toString('hex');
  return {publicKey:pubkey,privateKey:privkey};
}

/*
** bcrypto routine wrappers
*/
function _decrypt(msg, iv, key) { return aes.decipher(Buffer.from(msg,'hex'),Buffer.from(key,'hex'),Buffer.from(iv,'hex')) }
function _encrypt(msg, key) {
  let iv = randomBytes(16);
  return {cyphertext:aes.encipher(Buffer.from(msg),Buffer.from(key,'hex'),iv).toString('hex'), iv:iv.toString('hex')};
}
function _ecdh(pub,priv) { return sha256.digest(secp256k1.derive(Buffer.from(pub,'hex'),Buffer.from(priv,'hex'), true)).toString('hex') }

module.exports = { encrypt, decrypt }
