# SshKey
This library allows you to work with public and private keys in PHP.

- Read keys both from a file and from other sources like a database
- Convert between key formats
- Get a public keys fingerprint
- Generate new key-pairs

It depends on [phpseclib](https://github.com/phpseclib/phpseclib) for all of the key manipulation.

## Installation
Require the package in your **composer.json** and then run `composer update`

    "require": {
        ...
        "codeaken/sshkey": "1.*"
        ...
    },

## Usage

These examples makes the following assumptions:

- The library is autoloaded, for example by having included `vendor/autoload.php` somewhere in your project
- You have a a key-pair in your current directory called `id_rsa` (private) and `id_rsa.pub` (public). The private key is not encrypted.
- An encrypted private key in your current directory called `id_encrypted_rsa` protected by the password `abc123`

### Read a key from a file

    <?php

    // Read in the public and private keys
    $publicKey = SshPublicKey::fromFile('id_rsa.pub');
    $privateKey = SshPrivateKey::fromFile('id_rsa');
    $encryptedPrivateKey = SshPrivateKey::fromFile('id_encrypted_rsa', 'abc123');

    // Try to read a key that does not exists; will throw a FileNotFoundException
    try {
        $missingKey = SshPublicKey::fromFile('nosuchkey.pub');
    }
    catch (Codeaken\SshKey\Exception\FileNotFoundException $e)
    {
        echo 'Could not find the key';
    }

    // Try to read an encrypted private key using the wrong password; will throw a
    // LoadKeyException
    try {
        $encryptedKey = SshPrivateKey::fromFile('id_encrypted_rsa', 'wrongpass');
    }
    catch (Codeaken\SshKey\Exception\LoadKeyException $e)
    {
        echo 'Could not decrypt the private key';
    }


### Read a key from a non file source

    <?php

    // In this case we will read the key data from a file for simplicity but it
    // could come from a database or some other source

    $publicKeyData = file_get_contents('id_rsa.pub');
    $publicKey = new SshPublicKey($publicKeyData);

    $encryptedPrivateKeyData = file_get_contents('id_encrypted_rsa');
    $privateKey = new SshPrivateKey($encryptedPrivateKeyData, 'abc123');

### Get a public keys fingerprint and comment

    <?php

    $publicKey = SshPublicKey::fromFile('id_rsa.pub');

    echo $publicKey->getFingerprint();
    echo $publicKey->getComment();

### Generate a new keypair

    <?php

    // 1024 bits and no passphrase
    $keyPair1 = SshKeyPair::generate(1024);

    // 2048 bits and a passphrase of abc123
    $keyPair2 = SshKeyPair::generate(2048, 'abc123');

    echo $keyPair2->getPrivateKey()->getKeyData(SshKey::FORMAT_PKCS8);
    echo $keyPair2->getPublicKey()->getKeyData(SshKey::FORMAT_OPENSSH);

### Save a key to a file

    <?php

    $keyPair = SshKeyPair::generate();

    $publicKey  = $keyPair->getPublicKey();
    $privateKey = $keyPair->getPrivateKey();

    file_put_contents('id_new_rsa.pub', $publicKey->getKeyData(SshKey::FORMAT_OPENSSH));
    file_put_contents('id_new_rsa', $privateKey->getKeyData(SshKey::FORMAT_PKCS8));

## License
SshKey is licensed under the [MIT License](http://opensource.org/licenses/MIT).

Copyright 2014 Magnus Johansson
