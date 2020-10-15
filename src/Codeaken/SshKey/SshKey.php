<?php
namespace Codeaken\SshKey;

use phpseclib\Crypt\RSA;

abstract class SshKey
{
    protected $key;

    const FORMAT_OPENSSH = 'openssh';
    const FORMAT_PKCS1   = 'pkcs1';
    const FORMAT_PKCS8   = 'pkcs8';
    const PRIVATE_FORMAT_PUTTY = 'puttyprivatekey'; // FOR GENERATING PUTTY FORMATED PRIVATE KEY
    const PUBLIC_FORMAT_OPENSSH = 'puttypublickey'; // FOR MATHCING THE PUBLIC KEY WITH PUTTY FORMATED PRIVATE KEY
    
    public function __construct()
    {
        $this->key = new RSA();
    }

    public function getKeyData($format)
    {
        $formatToConstant = [
            self::FORMAT_OPENSSH => RSA::PUBLIC_FORMAT_OPENSSH,
            self::FORMAT_PKCS1   => RSA::PUBLIC_FORMAT_PKCS1,
            self::FORMAT_PKCS8   => RSA::PUBLIC_FORMAT_PKCS8,
            self::PRIVATE_FORMAT_PUTTY => RSA::PRIVATE_FORMAT_PUTTY,
            self::PUBLIC_FORMAT_OPENSSH => RSA::PUBLIC_FORMAT_OPENSSH,            
        ];

        if ( ! isset($formatToConstant[$format])) {
            throw new \DomainException("Invalid format: $format");
        }

        if ('private' == $this->getKeyType()) {
            return $this->key->getPrivateKey($formatToConstant[$format]);
        } else {
            return $this->key->getPublicKey($formatToConstant[$format]);
        }
    }

    abstract protected function getKeyType();

    protected static function readFile($filename)
    {
        if ( ! file_exists($filename)) {
            throw new Exception\FileNotFoundException($filename);
        }

        $fileData = file_get_contents($filename);

        if (false === $fileData) {
            throw new Exception\FileReadException($filename);
        }

        return $fileData;
    }
}
