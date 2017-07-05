<?php

use Amp\Loop;
use Amp\WindowsRegistry\WindowsRegistry;
use Kelunik\Certificate\Certificate;

require __DIR__ . "/../vendor/autoload.php";

Loop::run(function () {
    $certs = yield (new Kelunik\WindowsCertStore\CertQuery(new WindowsRegistry))->listAllCas();

    foreach ($certs as $cert) {
        $cert = new Certificate($cert);
        print $cert->getSubject()->getCommonName() . PHP_EOL;
    }
});