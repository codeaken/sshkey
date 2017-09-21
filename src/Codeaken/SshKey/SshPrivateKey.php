<?php
namespace Codeaken\SshKey;

class SshPrivateKey extends SshKey
{
    private $password;

    public function __construct($keyData, $password = '')
    {
        parent::__construct();

        $this->password = $password;

        if ( ! empty($password)) {
            $this->key->setPassword($password);
        }

        if ( ! $this->key->loadKey($keyData)) {
            throw new Exception\LoadKeyException();
        }
    }

    public function getPublicKey($format = self::FORMAT_OPENSSH)
    {
        $keyData = $this->key->getPublicKey($this->formatToConstant[$format]);

        return new SshPublicKey($keyData);
    }

    public static function fromFile($filename, $password = '')
    {
        return new SshPrivateKey(SshKey::readFile($filename), $password);
    }

    public function hasPassword()
    {
        return !empty($this->password);
    }

    public function getPassword()
    {
        return $this->password;
    }

    protected function getKeyType()
    {
        return 'private';
    }
}
