<?php
namespace Codeaken\SshKey;

class SshPublicKey extends SshKey
{
    public function __construct(string $keyData, string $comment = null)
    {
        parent::__construct();

        if ( ! $this->key->loadKey($keyData)) {
            throw new Exception\LoadKeyException();
        }

        if ($comment) {
            $this->setComment($comment);
        }
    }

    public static function fromPrivateKey(SshPrivateKey $privateKey, $format = self::FORMAT_OPENSSH)
    {
        return $privateKey->getPublicKey($format);
    }

    public static function fromFile($filename)
    {
        return new self(SshKey::readFile($filename));
    }

    public function getFingerprint()
    {
        $keyParts = explode(' ', $this->getKeyData(SshKey::FORMAT_OPENSSH));

        return implode(':', str_split(md5(base64_decode($keyParts[1])), 2));
    }

    public function setComment($comment)
    {
        $this->key->setComment($comment);

        return $this;
    }

    public function getComment()
    {
        return trim($this->key->getComment());
    }

    protected function getKeyType()
    {
        return 'public';
    }
}
