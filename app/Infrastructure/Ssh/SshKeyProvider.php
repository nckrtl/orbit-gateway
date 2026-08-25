<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

interface SshKeyProvider
{
    public function privateKeyPath(): string;

    public function publicKey(): string;
}
