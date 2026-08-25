<?php

declare(strict_types=1);

namespace App\Domain\Certificates;

interface GatewayCertificateIssuer
{
    public function issue(string $hostname, string $wireguardAddress): GatewayCertificatePaths;
}
