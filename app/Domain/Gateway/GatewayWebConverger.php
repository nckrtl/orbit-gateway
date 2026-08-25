<?php

declare(strict_types=1);

namespace App\Domain\Gateway;

interface GatewayWebConverger
{
    public function converge(string $hostname, string $wireguardAddress): void;
}
