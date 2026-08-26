<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevSourceOperationLock;
use Closure;
use RuntimeException;

final class NativeAppDevSourceOperationLock implements AppDevSourceOperationLock
{
    /** @var array<int, true> */
    private array $heldNodes = [];

    public function __construct(
        private readonly string $directory,
    ) {}

    public function synchronized(int $nodeId, Closure $operation): mixed
    {
        if (array_key_exists($nodeId, $this->heldNodes)) {
            return $operation();
        }

        if (
            ! is_dir($this->directory)
            && ! mkdir(directory: $this->directory, permissions: 0o700, recursive: true)
            && ! is_dir($this->directory)
        ) {
            throw new RuntimeException("Could not create source lock directory [{$this->directory}].");
        }

        chmod(filename: $this->directory, permissions: 0o700);
        $path = "{$this->directory}/node-{$nodeId}.lock";
        $handle = fopen(filename: $path, mode: 'c+');

        if ($handle === false) {
            throw new RuntimeException("Could not open source lock [{$path}].");
        }

        try {
            chmod(filename: $path, permissions: 0o600);

            if (! flock($handle, LOCK_EX)) {
                throw new RuntimeException("Could not acquire source lock [{$path}].");
            }

            $this->heldNodes[$nodeId] = true;

            return $operation();
        } finally {
            unset($this->heldNodes[$nodeId]);
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
