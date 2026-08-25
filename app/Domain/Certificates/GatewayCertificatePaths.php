<?php

declare(strict_types=1);

namespace App\Domain\Certificates;

final readonly class GatewayCertificatePaths
{
    public function __construct(
        public string $privateKeyPath,
        public string $certificatePath,
    ) {}
}
