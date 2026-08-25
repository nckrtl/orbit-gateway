<?php

declare(strict_types=1);

namespace App\Domain\Certificates;

interface LeafCertificateSigner
{
    public function sign(string $hostname, string $certificateRequest): string;

    public function rootCertificate(): string;
}
