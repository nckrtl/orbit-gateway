<?php

declare(strict_types=1);

namespace App\Domain\Instances;

enum CertificateMode: string
{
    case OrbitCa = 'orbit-ca';
    case Acme = 'acme';
}
