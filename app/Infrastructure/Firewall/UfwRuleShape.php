<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

/** @mago-expect lint:excessive-parameter-list The value keeps the complete comparable UFW shape typed. */
final readonly class UfwRuleShape
{
    public function __construct(
        public string $comment,
        public string $action,
        public string $direction,
        public string $source,
        public string $destination,
        public string $port,
        public string $protocol,
        public ?string $inInterface,
        public ?string $outInterface,
        public ?string $family,
    ) {}

    public function matches(self $observed): bool
    {
        return (
            $this->comment === $observed->comment
            && $this->action === $observed->action
            && $this->direction === $observed->direction
            && $this->source === $observed->source
            && $this->destination === $observed->destination
            && $this->port === $observed->port
            && $this->protocol === $observed->protocol
            && $this->inInterface === $observed->inInterface
            && $this->outInterface === $observed->outInterface
            && ($this->family === null || $this->family === $observed->family)
        );
    }
}
