<?php

declare(strict_types=1);

namespace Tests\Support;

/** @mago-expect lint:excessive-parameter-list The result captures each observable publication and recovery effect. */
final readonly class AppDevCaddyPublishResult
{
    /**
     * @param array<string, string> $publishedFragments
     * @param list<string> $serviceCalls
     */
    public function __construct(
        public int $exitCode,
        public string $stdout,
        public string $stderr,
        public string $liveMainAfter,
        public array $publishedFragments,
        public ?string $liveLinkTargetAfter,
        public array $serviceCalls,
    ) {}
}
