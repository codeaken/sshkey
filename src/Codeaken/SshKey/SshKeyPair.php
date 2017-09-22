<?php
namespace Codeaken\SshKey;

use Codeaken\SshKey\Exception\InvalidKeyTypeException;
use phpseclib\Crypt\RSA;

class SshKeyPair
{
    /** @var  SshPublicKey */
    private $publicKey;

    /** @var  SshPrivateKey */
    private $privateKey;

    public function __construct(SshPrivateKey $privateKey, SshPublicKey $publicKey = null)
    {
        $this->privateKey = $privateKey;
        $this->publicKey  = $publicKey;

        if (!$publicKey) {
            $this->publicKey = $privateKey->getPublicKey();
        }
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    public static function fromFile($filename, $password = '')
    {
        $privateKey = SshPrivateKey::fromFile($filename, $password);

        if ('' == $privateKey->getKeyData()) {
            throw new InvalidKeyTypeException('You have to create a KeyPair from a Private Key');
        }

        return new self($privateKey);
    }

    public static function generate(int $bits = 4096, string $password = '')
    {
        $bits = (int)$bits;

        $rsa = new RSA();

        if ( ! empty($password)) {
            $rsa->setPassword($password);
        }

        $keys = $rsa->createKey($bits);

        $publicKey  = new SshPublicKey($keys['publickey']);
        $privateKey = new SshPrivateKey($keys['privatekey'], $password);

        return new self($privateKey, $publicKey);
    }
}
