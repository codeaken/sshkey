<?php
namespace Codeaken\SshKey;

use phpseclib\Crypt\RSA;

abstract class SshKey
{
    protected $key;

    const FORMAT_OPENSSH = 'openssh';
    const FORMAT_PKCS1   = 'pkcs1';
    const FORMAT_PKCS8   = 'pkcs8';
    const FORMAT_PUTTY   = 'putty';

    protected $formatToConstant = [
        self::FORMAT_OPENSSH => RSA::PUBLIC_FORMAT_OPENSSH,
        self::FORMAT_PKCS1   => RSA::PUBLIC_FORMAT_PKCS1,
        self::FORMAT_PKCS8   => RSA::PUBLIC_FORMAT_PKCS8,
        self::FORMAT_PUTTY   => RSA::PRIVATE_FORMAT_PUTTY,
    ];

    public function __construct()
    {
        $this->key = new RSA();
    }

    public function getKeyData($format = self::FORMAT_OPENSSH)
    {
        if ( ! isset($this->formatToConstant[$format])) {
            throw new \DomainException("Invalid format: $format");
        }

        if ('private' == $this->getKeyType()) {
            $keyData =  $this->key->getPrivateKey($this->formatToConstant[$format]);
        } else {
            $keyData = $this->key->getPublicKey($this->formatToConstant[$format]);
        }

        if ($format != self::FORMAT_PUTTY) {
            $keyData = $this->normalizeLineEndings($keyData);
        }

        return $keyData;
    }

    public function getSize()
    {
        return $this->key->getSize();
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

    protected function normalizeLineEndings($data)
    {
        return str_replace("\r\n", "\n", $data);
    }
}
