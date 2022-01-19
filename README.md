# hsencrypt
## nodejs library to encrypt or decrypt messages using handshake names

hsencrypt uses handshake names, a handshake node, and a handshake wallet to encrypt and decrypt names.  Using ephemeral keys instead of the original implementation of hsencrypt which used only the static keys, we are able to gain some benefits.

Instead of requiring long term secrecy of two private keys (sender and receiver), the new implementation only requires a long term private key of the receiver.

## How to use

```
npm install hsencrypt
```

```
encrypt(wallet, node, passphrase, name, target, message) 
decrypt(wallet, node, passphrase, name, sender, ciphertext)
```

```
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
```

```
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
```

## Example

You can see it in action in [zmsg](https://github.com/publiusfederalist/zmsg).

Also, feel free to try the following example which assumes a folder `keys` includes files `node` and `wallet` with the associated api keys inside them.  It also, of course, requires hsd, hs-client and consoleinout npms.

```
#!/usr/bin/env node
const {encrypt, decrypt} = require("hsencrypt");
const {WalletClient, NodeClient} = require('hs-client');
const {Network} = require('hsd');
const fs = require('fs');
const network = Network.get('main');
const ConsoleIO = new (require("consoleinout"))(console);

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
    console.log("Decrypt Usage: ",argv[1],"<wallet>","<from>","<to>","\"<encrypted-msg>\"", "\"d\"");
    process.exit();
  }
  walletClient = _walletClient.wallet(argv[2]);
  if(!walletClient) {
    console.log("Wallet ",argv[2],"not found");
    process.exit(0);
  }

  console.output("Enter Password: ");
  const password = await console.input(true);

  if(argc==7) {
    let decrypted=await decrypt(walletClient, nodeClient, password, argv[4], argv[3], argv[5]);
    console.log("Decrypted: ",decrypted);
    process.exit(0);
  }
  else if(argc==6) {
    let encrypted=await encrypt(walletClient, nodeClient, password, argv[3], argv[4], argv[5]);
    console.log(encrypted);
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
