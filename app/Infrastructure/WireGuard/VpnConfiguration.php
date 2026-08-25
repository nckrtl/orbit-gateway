<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Models\Node;

/** @mago-expect lint:excessive-parameter-list */
final readonly class VpnConfiguration
{
    public function __construct(
        public Node $server,
        public string $subnet,
        public int $prefixLength,
        public int $port,
        public string $endpoint,
        public string $dnsServer,
        public string $domain,
        public string $serverAddress,
        public string $peerAddress,
        public string $serverPrivateKey,
        public string $serverPublicKey,
    ) {}
}
