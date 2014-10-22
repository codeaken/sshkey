<?php
namespace Codeaken\SshKey\Exception;

class FileNotFoundException extends \Exception
{
    public function __construct($filename)
    {
        parent::__construct("File '$filename' not found");
    }
}
