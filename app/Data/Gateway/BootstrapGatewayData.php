<?php

declare(strict_types=1);

namespace App\Data\Gateway;

use Spatie\LaravelData\Data;

/** @mago-expect lint:excessive-parameter-list */
final class BootstrapGatewayData extends Data
{
    public function __construct(
        public string $publicHost,
        public string $wireguardAddress,
        public string $wireguardSubnet,
        public string $wireguardEndpoint,
        public string $dnsServer,
        public string $domain,
        public ?string $privateInterface = null,
        public int $wireguardPort = 51_820,
        public string $name = 'gateway',
    ) {}
}
