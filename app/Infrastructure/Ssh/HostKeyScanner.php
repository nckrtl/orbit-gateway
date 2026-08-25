<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

interface HostKeyScanner
{
    public function scan(string $host, int $port): HostKey;
}
