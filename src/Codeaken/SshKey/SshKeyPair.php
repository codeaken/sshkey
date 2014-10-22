<?php
namespace Codeaken\SshKey;

class SshKeyPair
{
    private $publicKey;
    private $privateKey;

    public function __construct($publicKey, $privateKey)
    {
        $this->publicKey  = $publicKey;
        $this->privateKey = $privateKey;
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    public static function generate($bits = 2048, $password = '')
    {
        $bits = (int)$bits;

        $rsa = new \Crypt_RSA();

        if ( ! empty($password)) {
            $rsa->setPassword($password);
        }

        $keys = $rsa->createKey($bits);

        $publicKey  = new SshPublicKey($keys['publickey']);
        $privateKey = new SshPrivateKey($keys['privatekey'], $password);

        return new SshKeyPair($publicKey, $privateKey);
    }
}
