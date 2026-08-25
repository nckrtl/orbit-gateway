<?php

declare(strict_types=1);

namespace App\Data\Instances;

/** @mago-expect lint:excessive-parameter-list The request has six independent scalar fields. */
final readonly class CreateInstanceData
{
    public function __construct(
        public int $appId,
        public int $nodeId,
        public string $name,
        public string $environment,
        public string $documentRoot,
        public string $phpVersion,
    ) {}
}
