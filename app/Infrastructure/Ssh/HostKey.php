<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

final readonly class HostKey
{
    public function __construct(
        public string $type,
        public string $value,
        public string $fingerprint,
    ) {}
}
