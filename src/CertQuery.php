<?php

namespace Kelunik\WindowsCertStore;

use Amp\Promise;
use Amp\WindowsRegistry\WindowsRegistry;
use Kelunik\Certificate\Certificate;
use function Amp\call;

class CertQuery {
    private $registry;

    public function __construct(WindowsRegistry $registry) {
        $this->registry = $registry;
    }

    public function listMicrosoftCas() {
        return $this->listCertificates('HKEY_Local_Machine\Software\Microsoft\SystemCertificates\Root\Certificates');
    }

    public function listThirdPartyCas() {
        return $this->listCertificates('HKEY_Local_Machine\Software\Microsoft\SystemCertificates\AuthRoot\Certificates');
    }

    public function listAllCas() {
        return call(function () {
            list($ms, $thirdParty) = yield [
                $this->listMicrosoftCas(),
                $this->listThirdPartyCas(),
            ];

            return array_merge($ms, $thirdParty);
        });
    }

    public function listCertificates(string $key): Promise {
        return call(function () use ($key) {
            $certs = [];

            foreach (yield $this->registry->listKeys($key) as $certKey) {
                $data = yield $this->registry->read($certKey);

                // Windows uses a 12 byte header
                // See https://namecoin.org/2017/05/27/reverse-engineering-cryptoapi-cert-blobs.html
                $derCert = \substr(\hex2bin($data[2]), 12);
                $pemCert = Certificate::derToPem($derCert);

                $certs[] = $pemCert;
            }

            return $certs;
        });
    }
}