<?php

declare(strict_types=1);

namespace App\Domain\Processes;

use App\Models\Instance;
use App\Models\Workspace;

enum ProcessTargetType: string
{
    case Instance = 'instance';
    case Workspace = 'workspace';

    /** @return class-string<Instance|Workspace> */
    public function modelClass(): string
    {
        return match ($this) {
            self::Instance => Instance::class,
            self::Workspace => Workspace::class,
        };
    }

    public static function fromModelClass(string $modelClass): self
    {
        return match ($modelClass) {
            Instance::class => self::Instance,
            Workspace::class => self::Workspace,
            default => throw new \InvalidArgumentException('Unsupported process target model.'),
        };
    }
}
