<?php

declare(strict_types=1);

namespace App\Data\Firewall;

use App\Domain\Firewall\FirewallBackendStatus;
use App\Models\FirewallRule;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class FirewallRuleData extends Data
{
    /** @mago-expect lint:excessive-parameter-list */
    public function __construct(
        public int $id,
        public int $nodeId,
        public string $node,
        public string $name,
        public string $action,
        public string $source,
        public string $protocol,
        public string $port,
        public string $status,
        public ?string $backendStatus,
        public ?string $failedStep,
        public ?string $errorCode,
    ) {}

    public static function fromModel(
        FirewallRule $rule,
        ?FirewallBackendStatus $backendStatus = null,
    ): self {
        $rule->loadMissing('node');

        return new self(
            id: $rule->id,
            nodeId: $rule->node_id,
            node: $rule->node->name,
            name: $rule->name,
            action: $rule->action->value,
            source: $rule->source,
            protocol: $rule->protocol,
            port: $rule->port,
            status: $rule->status->value,
            backendStatus: $backendStatus?->value,
            failedStep: $rule->failed_step,
            errorCode: $rule->error_code,
        );
    }
}
