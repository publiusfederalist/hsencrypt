const {randomBytes} = require('bcrypto/lib/random');
const aead = require('bcrypto/lib/aead');
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
**   returns pubKey+ciphertext
**     pubKey     - an ephemeral public key
**     ciphertext - an AEAD encrypted message (chacha20 x poly1305)
**     or null
***
****/
async function encrypt(wallet, node, passphrase, name, target, message) {
  const keys = await getKeysFromName(wallet, node, passphrase, name);
  const targetPubkey = await getPubkeyFromName(node, target);
  const ephemeralKeys = _genEphemeral();
  const secret = _genEphemeralSenderKey(keys.privateKey, ephemeralKeys.privKey, targetPubkey);
  return ephemeralKeys.pubKey+_encrypt(message, secret);
}

/****
***
** decrypt()
**   wallet          - Wallet from hsd
**   node            - Node from hsd
**   passphrase      - passphrase for wallet
**   name            - my name
**   sender          - sender's name
**   ciphertext      - ephemeralPubKey + the ciphertext
**
**   returns
**     string containing the decrypted message
**     or null
***
****/
async function decrypt(wallet, node, passphrase, name, sender, ciphertext) {
  const keys = await getKeysFromName(wallet, node, passphrase, name);
  const senderPubkey = await getPubkeyFromName(node, sender);
  if(ciphertext.length<=67)
    return null;
  const ephemeralPubkey = ciphertext.substr(0,66);
  ciphertext=ciphertext.substr(66);
  const secret = _genEphemeralTargetKey(keys.privateKey, ephemeralPubkey, senderPubkey);
  return _decrypt(ciphertext, secret);
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
  privkey58 = base58.decode(privWIF).slice(1);
  _tmp = new Buffer.alloc(privkey58.length - 5);
  privkey58.copy(_tmp, 0, 0, privkey58.length - 5);
  privkey58=_tmp;
  pubkey = secp256k1.publicKeyCreate(privkey58, true).toString('hex');
  privkey = privkey58.toString('hex');
  return {publicKey:pubkey,privateKey:privkey};
}

/*
** bcrypto routine wrappers
*/
function _decrypt(msg, key) {
  if(msg.length<32)
    return null;
  let _msg = Buffer.from(msg.substr(0,msg.length-32),'hex');
  let _tag = msg.substr(msg.length-32);
  let _aead = aead.decrypt(Buffer.from(key,'hex'),Buffer.alloc(8,0,'hex'),_msg,Buffer.from(_tag,'hex'));

  if(_aead)
    return _msg.toString();
  else
    return null;
}
function _encrypt(msg, key) {
  let cipher = Buffer.from(msg);
  let encrypted = aead.encrypt(Buffer.from(key, 'hex'),Buffer.alloc(8,0,'hex'),cipher);
  return cipher.toString('hex')+encrypted.toString('hex');
}
function _genEphemeral() {
  const privKey = secp256k1.privateKeyGenerate();
  const pubKey = secp256k1.publicKeyCreate(privKey, true);
  return {privKey:privKey.toString('hex'),pubKey:pubKey.toString('hex')};
}
function _genEphemeralSenderKey(privSender, privEphemeral, pubTarget) {
  const myECDH1 = sha256.digest(secp256k1.derive(Buffer.from(pubTarget,'hex'),Buffer.from(privEphemeral,'hex'), true));
  const myECDH2 = sha256.digest(secp256k1.derive(Buffer.from(pubTarget,'hex'),Buffer.from(privSender,'hex'), true));
  return sha256.digest(Buffer.concat([myECDH1,myECDH2],myECDH1.length+myECDH2.length)).toString('hex');
}
function _genEphemeralTargetKey(privTarget, pubEphemeral, pubSender) {
  const myECDH1 = sha256.digest(secp256k1.derive(Buffer.from(pubEphemeral,'hex'),Buffer.from(privTarget,'hex'), true));
  const myECDH2 = sha256.digest(secp256k1.derive(Buffer.from(pubSender,'hex'),Buffer.from(privTarget,'hex'), true));
  return sha256.digest(Buffer.concat([myECDH1,myECDH2],myECDH1.length+myECDH2.length)).toString('hex');
}

module.exports = { encrypt, decrypt }

