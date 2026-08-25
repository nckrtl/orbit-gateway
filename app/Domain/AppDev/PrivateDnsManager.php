<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

interface PrivateDnsManager
{
    public function converge(): void;
}
