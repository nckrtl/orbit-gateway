<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

/** @mago-expect lint:excessive-parameter-list A site is one immutable rendered production runtime record. */
final readonly class AppProdSite
{
    public function __construct(
        public int $nodeId,
        public string $appSlug,
        public string $instanceName,
        public string $checkoutPath,
        public string $documentRoot,
        public string $phpVersion,
        public string $hostname,
        public int $instanceId,
    ) {}

    public function user(): string
    {
        return "orbit-{$this->appSlug}";
    }

    public function scope(): string
    {
        return "instance-{$this->instanceId}";
    }

    public function poolName(): string
    {
        return "orbit-prod-{$this->scope()}";
    }

    public function socketPath(): string
    {
        return "/run/php/{$this->poolName()}.sock";
    }

    public function appRoot(): string
    {
        return "/var/www/{$this->appSlug}";
    }
}
