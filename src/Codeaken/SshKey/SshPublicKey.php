<?php
namespace Codeaken\SshKey;

class SshPublicKey extends SshKey
{
    public function __construct($keyData)
    {
        parent::__construct();

        $this->key->loadKey($keyData);
    }

    public static function fromFile($filename)
    {
        return new SshPublicKey(SshKey::readFile($filename));
    }

    protected function getKeyType()
    {
        return 'public';
    }
}
