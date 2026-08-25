<?php

declare(strict_types=1);

namespace Tests\Support;

final readonly class AppDevCaddyPublishResult
{
    /** @param array<string, string> $publishedFragments */
    public function __construct(
        public int $exitCode,
        public string $stdout,
        public string $stderr,
        public string $liveMainAfter,
        public array $publishedFragments,
    ) {}
}
