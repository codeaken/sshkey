<?php

error_reporting(E_ALL);
ini_set('display_errors', true);

require 'vendor/autoload.php';

use Codeaken\SshKey\SshPublicKey;
use Codeaken\SshKey\SshPrivateKey;
use Codeaken\SshKey\SshKeyPair;

/*
echo 'Hello world';
$pair = SshKeyPair::generate(2048, 'secret');
var_dump($pair->getPrivateKey()->getKeyData('pkcs8'));
var_dump($pair->getPublicKey()->getKeyData('pkcs1'));
*/

$key = SshPublicKey::fromFile('do1_rsa.pub');
var_dump($key->getKeyData('pkcs1'));
var_dump($key->getKeyData('openssh'));

$key = SshPrivateKey::fromFile('do1_rsa');
var_dump($key->getKeyData('pkcs1'));
var_dump($key->getKeyData('openssh'));

var_dump(SshKeyPair::generate());
