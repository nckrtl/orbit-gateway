<?php

declare(strict_types=1);

namespace App\Data\Instances;

use App\Models\Instance;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** @mago-expect lint:excessive-parameter-list */
#[MapOutputName(SnakeCaseMapper::class)]
final class InstanceData extends Data
{
    public function __construct(
        public int $id,
        public int $appId,
        public int $nodeId,
        public string $name,
        public string $environment,
        public string $checkoutPath,
        public string $documentRoot,
        public string $phpVersion,
        public string $hostname,
        public string $certificateMode,
        public string $status,
        public ?string $failedStep,
        public ?string $errorCode,
    ) {}

    public static function fromModel(Instance $instance): self
    {
        /** @var ?string $failedStep */
        $failedStep = $instance->getAttribute('failed_step');
        /** @var ?string $errorCode */
        $errorCode = $instance->getAttribute('error_code');

        return new self(
            id: $instance->id,
            appId: $instance->app_id,
            nodeId: $instance->node_id,
            name: $instance->name,
            environment: $instance->environment,
            checkoutPath: $instance->checkout_path,
            documentRoot: $instance->document_root,
            phpVersion: $instance->php_version,
            hostname: $instance->hostname,
            certificateMode: $instance->certificate_mode->value,
            status: $instance->status->value,
            failedStep: $failedStep,
            errorCode: $errorCode,
        );
    }
}
