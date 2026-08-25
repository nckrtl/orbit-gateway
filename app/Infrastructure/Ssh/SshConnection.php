<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

/** @mago-expect lint:excessive-parameter-list */
final readonly class SshConnection
{
    public function __construct(
        public string $host,
        public string $user,
        public int $port,
        public string $identityFile,
        public string $knownHostsFile,
        public int $connectTimeout = 10,
        public float $commandTimeout = 900.0,
    ) {}
}
