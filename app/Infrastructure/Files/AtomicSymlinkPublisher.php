<?php

declare(strict_types=1);

namespace App\Infrastructure\Files;

interface AtomicSymlinkPublisher
{
    public function publish(string $target, string $link): void;
}
