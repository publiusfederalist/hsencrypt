# hsencrypt
## nodejs library to encrypt or decrypt messages using handshake names

hsencrypt uses handshake names, a handshake node, and a handshake wallet to encrypt and decrypt names

## How to use

```
encrypt(wallet, node, passphrase, name, target, message) 
decrypt(wallet, node, passphrase, name, sender, ciphertext, iv)
```

## Example

The following example assumes a folder `keys` includes files `node` and `wallet` with the associated api keys inside them.

```
#!/usr/bin/env node
const {encrypt, decrypt} = require("hsencrypt");
const {WalletClient, NodeClient} = require('hs-client');
const {Network} = require('hsd');
const fs = require('fs');
const network = Network.get('main');
const readline = require('readline');
const writable = require('stream').Writable;

var mutable = new writable({
  write: function(chunk, encoding, callback) {
    if (!this.muted)
      process.stdout.write(chunk, encoding);
    callback();
  }
});
const rl = readline.createInterface({
  input: process.stdin,
  output: mutable,
  terminal: true
});
mutable.muted = false;

const nodeOptions = {
  network: network.type,
  port: network.rpcPort,
  apiKey: fs.readFileSync("keys/node").toString().trim()
}
const walletOptions = {
  port: network.walletPort,
  apiKey: fs.readFileSync("keys/wallet").toString().trim()
}
const nodeClient = new NodeClient(nodeOptions);
const _walletClient = new WalletClient(walletOptions);
let walletClient;

(async function() {
  const argv=process.argv;
  const argc=argv.length;

  if(argc!=6 && argc!=7) {
    console.log("Encrypt Usage: ",argv[1],"<wallet>","<from>","<to>","\"<msg>\"");
    console.log("");
    console.log("Decrypt Usage: ",argv[1],"<wallet>","<from>","<to>","\"<encrypted-msg>\"","\"<IV>\"");
    process.exit();
  }
  walletClient = _walletClient.wallet(argv[2]);
  if(!walletClient) {
    console.log("Wallet ",argv[2],"not found");
    process.exit(0);
  }

  console.log("Enter Password:");
  const it = rl[Symbol.asyncIterator]();
  mutable.muted = true;
  const password = (await it.next()).value
  mutable.muted = false;

  if(argc==7) {
    let decrypted=await decrypt(walletClient, nodeClient, password, argv[4], argv[3], argv[5], argv[6]);
    console.log("Decrypted: ",decrypted.toString());
    process.exit(0);
  }
  else if(argc==6) {
    let encrypted=await encrypt(walletClient, nodeClient, password, argv[3], argv[4], argv[5]);
    console.log("Encrypted: ",encrypted.cyphertext);
    console.log("IV: ",encrypted.iv);
    process.exit(0);
  }
})()

```

## Learn More

[Discord](https://discord.gg/tXJ2UdGuda)

[Github](https://github.com/publiusfederalist)

## License

Copyright (c) 2022 Publius Federalist
All Rights Reserved

MIT Licensed