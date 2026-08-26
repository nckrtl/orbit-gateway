<?php

declare(strict_types=1);

namespace App\Data\Processes;

use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessTargetType;
use SensitiveParameter;

/** @mago-expect lint:excessive-parameter-list */
final readonly class AddProcessData
{
    /**
     * @param list<string> $command
     * @param array<string, string> $environment
     * @param list<string> $ports
     * @param list<array{source: string, target: string, read_only: bool}> $volumes
     */
    public function __construct(
        public ProcessTargetType $targetType,
        public int $targetId,
        public string $name,
        public ?ProcessRuntime $runtime,
        public array $command,
        public ?string $image,
        public ?string $workingDirectory,
        #[SensitiveParameter]
        public array $environment,
        public array $ports,
        public array $volumes,
        public string $restartPolicy,
        public bool $start,
    ) {}
}
