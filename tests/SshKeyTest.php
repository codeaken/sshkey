<?php
namespace Codeaken\SshKey\Tests;

use Codeaken\SshKey\SshKey;
use Codeaken\SshKey\SshPublicKey;
use Codeaken\SshKey\SshPrivateKey;
use Codeaken\SshKey\SshKeyPair;

class SshKeyTest extends \PHPUnit_Framework_TestCase
{
    protected $keysDir;

    protected function setUp()
    {
        $this->keysDir = dirname(__FILE__) . '/keys';
    }

    public function testLoadPublicKeyFromNonExistentFile()
    {
        $this->setExpectedException('Codeaken\SshKey\Exception\FileNotFoundException');

        SshPublicKey::fromFile('id_missing_rsa.pub');
    }

    public function testLoadPrivateKeyFromNonExistentFile()
    {
        $this->setExpectedException('Codeaken\SshKey\Exception\FileNotFoundException');

        SshPrivateKey::fromFile('id_missing_rsa');
    }

    public function testLoadPublicKeyFromFile()
    {
        $key = SshPublicKey::fromFile("{$this->keysDir}/id_nopass_rsa.pub");
        $this->assertInstanceOf('Codeaken\SshKey\SshPublicKey', $key);
    }

    public function testLoadPrivateKeyFromFile()
    {
        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_nopass_rsa");
        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadEncryptedPrivateKeyFromFileWithNoPassword()
    {
        $this->setExpectedException('Codeaken\SshKey\Exception\LoadKeyException');

        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_pass_rsa");
        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadEncryptedPrivateKeyFromFileWithWrongPassword()
    {
        $this->setExpectedException('Codeaken\SshKey\Exception\LoadKeyException');

        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_pass_rsa", 'wrongpass');
        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadEncryptedPrivateKeyFromFile()
    {
        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_pass_rsa", 'abc123');
        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadPublicKeyFromString()
    {
        $keyContents = file_get_contents("{$this->keysDir}/id_nopass_rsa.pub");

        $key = new SshPublicKey($keyContents);

        $this->assertInstanceOf('Codeaken\SshKey\SshPublicKey', $key);
    }

    public function testLoadPrivateKeyFromString()
    {
        $keyContents = file_get_contents("{$this->keysDir}/id_nopass_rsa");

        $key = new SshPrivateKey($keyContents);

        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadPrivateKeyWithPasswordFromString()
    {
        $keyContents = file_get_contents("{$this->keysDir}/id_pass_rsa");

        $key = new SshPrivateKey($keyContents, 'abc123');

        $this->assertInstanceOf('Codeaken\SshKey\SshPrivateKey', $key);
    }

    public function testLoadPrivateKeyWithWrongPasswordFromString()
    {
        $this->setExpectedException('Codeaken\SshKey\Exception\LoadKeyException');

        $keyContents = file_get_contents("{$this->keysDir}/id_pass_rsa");

        $key = new SshPrivateKey($keyContents, 'wrongpass');
    }

    public function testPrivateKeyGetPassword()
    {
        // Private key without a password
        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_nopass_rsa");

        $this->assertFalse($key->hasPassword());
        $this->assertEquals('', $key->getPassword());

        // Private key with password
        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_pass_rsa", 'abc123');

        $this->assertTrue($key->hasPassword());
        $this->assertEquals('abc123', $key->getPassword());
    }

    public function testPublicKeyFingerprint()
    {
        $key = SshPublicKey::fromFile("{$this->keysDir}/id_nopass_rsa.pub");

        $this->assertEquals(
            '1b:77:c2:8a:23:c4:f2:24:af:34:69:d1:eb:23:1c:77',
            $key->getFingerprint()
        );

        $key = SshPublicKey::fromFile("{$this->keysDir}/id_pass_rsa.pub");

        $this->assertEquals(
            'cf:d1:86:e5:39:ec:da:d9:9f:7e:87:d2:cd:a7:8e:a6',
            $key->getFingerprint()
        );
    }

    public function testPublicKeyComment()
    {
        $key = SshPublicKey::fromFile("{$this->keysDir}/id_nopass_rsa.pub");

        $this->assertEquals('sshkey@test.com', $key->getComment());
    }

    public function testCreateKeyPair()
    {
        $keyPair = SshKeyPair::generate();

        $this->assertInstanceOf(
            'Codeaken\SshKey\SshPrivateKey', $keyPair->getPrivateKey()
        );
        $this->assertInstanceOf(
            'Codeaken\SshKey\SshPublicKey', $keyPair->getPublicKey()
        );
    }

    public function testCreateKeyPairWithPrivateKeyPassword()
    {
        $keyPair = SshKeyPair::generate(2048, 'abc123');

        $this->assertInstanceOf(
            'Codeaken\SshKey\SshPrivateKey', $keyPair->getPrivateKey()
        );
        $this->assertInstanceOf(
            'Codeaken\SshKey\SshPublicKey', $keyPair->getPublicKey()
        );

        $this->assertTrue($keyPair->getPrivateKey()->hasPassword());
        $this->assertEquals('abc123', $keyPair->getPrivateKey()->getPassword());
    }
}
