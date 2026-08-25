<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

/** @mago-expect lint:excessive-parameter-list A site is one immutable rendered runtime record. */
final readonly class AppDevSite
{
    public function __construct(
        public int $nodeId,
        public string $nodeAddress,
        public string $scope,
        public string $checkoutPath,
        public string $documentRoot,
        public string $phpVersion,
        public string $hostname,
    ) {}

    public function poolName(): string
    {
        return "orbit-{$this->scope}";
    }

    public function socketPath(): string
    {
        return "/run/php/{$this->poolName()}.sock";
    }

    public function certificateDirectory(): string
    {
        return "/etc/caddy/orbit-certificates/{$this->scope}/current";
    }
}
