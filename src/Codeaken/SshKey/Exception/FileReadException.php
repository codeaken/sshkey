<?php
namespace Codeaken\SshKey\Exception;

class FileReadException extends \Exception
{
    public function __construct($filename)
    {
        parent::__construct("File '$filename' was not readable");
    }
}
