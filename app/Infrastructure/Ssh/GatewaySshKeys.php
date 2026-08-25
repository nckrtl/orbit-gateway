<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use RuntimeException;

final readonly class GatewaySshKeys implements SshKeyProvider
{
    public function __construct(
        private string $privateKeyPath,
    ) {}

    public function privateKeyPath(): string
    {
        return $this->privateKeyPath;
    }

    public function publicKey(): string
    {
        $path = $this->privateKeyPath.'.pub';
        $publicKey = file_get_contents($path);

        if (! is_string($publicKey) || ! str_starts_with($publicKey, 'ssh-')) {
            throw new RuntimeException("The gateway SSH public key [{$path}] is missing or invalid.");
        }

        return trim($publicKey);
    }
}
