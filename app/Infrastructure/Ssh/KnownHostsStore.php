<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

interface KnownHostsStore
{
    public function path(): string;

    public function put(string $host, int $port, HostKey $key): void;
}
