<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use Spatie\LaravelData\Data;

/** @mago-expect lint:excessive-parameter-list */
final class ProvisionNodeData extends Data
{
    /** @param list<RoleName> $roles */
    public function __construct(
        public string $name,
        public string $publicSshHost,
        public array $roles = [],
        public int $publicSshPort = 22,
        public string $sshUser = 'root',
        public ?string $wireguardAddress = null,
        public ?string $wireguardEndpointOverride = null,
        public ?string $dnsServerOverride = null,
        public ?string $expectedSshHostFingerprint = null,
        public string $platform = 'linux',
        public ?string $architecture = null,
        public ?string $tld = null,
    ) {}
}
