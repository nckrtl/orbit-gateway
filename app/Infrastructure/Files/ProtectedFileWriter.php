<?php

declare(strict_types=1);

namespace App\Infrastructure\Files;

use RuntimeException;

final readonly class ProtectedFileWriter
{
    public function put(string $path, string $contents, int $permissions = 0o600): void
    {
        $directory = dirname($path);

        if (
            ! is_dir($directory)
            && ! mkdir(directory: $directory, permissions: 0o700, recursive: true)
            && ! is_dir($directory)
        ) {
            throw new RuntimeException("Could not create protected directory [{$directory}].");
        }

        chmod(filename: $directory, permissions: 0o700);
        $temporaryPath = $path.'.tmp';

        if (file_put_contents($temporaryPath, $contents, LOCK_EX) === false) {
            throw new RuntimeException("Could not write protected file [{$temporaryPath}].");
        }

        chmod(filename: $temporaryPath, permissions: $permissions);

        if (! rename($temporaryPath, $path)) {
            throw new RuntimeException("Could not install protected file [{$path}].");
        }
    }
}
