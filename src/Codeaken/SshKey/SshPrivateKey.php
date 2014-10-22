<?php
namespace Codeaken\SshKey;

class SshPrivateKey extends SshKey
{
    public function __construct($keyData, $password = '')
    {
        parent::__construct();

        if ( ! empty($password)) {
            $this->key->setPassword($password);
        }

        $this->key->loadKey($keyData);
    }

    public static function fromFile($filename, $password = '')
    {
        return new SshPrivateKey(SshKey::readFile($filename), $password);
    }

    protected function getKeyType()
    {
        return 'private';
    }
}
