<?php

declare(strict_types=1);

namespace App\Infrastructure\Files;

use RuntimeException;

final readonly class NativeAtomicSymlinkPublisher implements AtomicSymlinkPublisher
{
    public function publish(string $target, string $link): void
    {
        $candidate = $link.'.candidate.'.bin2hex(random_bytes(8));

        try {
            if (! symlink($target, $candidate)) {
                throw new RuntimeException("Could not create candidate link [{$candidate}].");
            }

            if (! rename($candidate, $link)) {
                throw new RuntimeException("Could not atomically publish link [{$link}].");
            }
        } finally {
            $this->cleanup($candidate);
        }
    }

    private function cleanup(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            unlink($path);
        }
    }
}
