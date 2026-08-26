<?php

declare(strict_types=1);

namespace App\Actions\Firewall;

use App\Data\Firewall\StoreFirewallRuleData;
use App\Domain\Firewall\FirewallAction;
use App\Domain\Firewall\FirewallBackendStatus;
use App\Domain\Firewall\FirewallManager;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Firewall\FirewallPort;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\FirewallRule;
use App\Models\Node;

final readonly class StoreFirewallRuleAction
{
    public function __construct(
        private FirewallManager $firewall,
    ) {}

    /** @return array{rule: FirewallRule, created: bool, backend_status: FirewallBackendStatus} */
    public function execute(Node $node, StoreFirewallRuleData $data): array
    {
        $this->guardRecoverySsh($node, $data);
        $rule = FirewallRule::query()->firstOrNew([
            'node_id' => $node->id,
            'name' => $data->name,
        ]);
        $created = ! $rule->exists;
        $attributes = [
            'action' => $data->action,
            'source' => $data->source,
            'protocol' => $data->protocol,
            'port' => $data->port,
        ];

        if ($rule->exists && ! $this->matches($rule, $attributes)) {
            throw new ResourceOperationException(
                errorCode: 'firewall.name_taken',
                message: "Firewall rule [{$data->name}] already exists with different configuration.",
                status: 409,
            );
        }

        $rule->fill([
            ...$attributes,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ])->save();
        $rule->setRelation('node', $node);

        try {
            $backendStatus = $this->firewall->converge($rule);

            if ($backendStatus === FirewallBackendStatus::Inactive) {
                throw $this->backendInactive($node);
            }
        } catch (FirewallOperationException $exception) {
            $rule->update([
                'status' => LifecycleStatus::Failed,
                'failed_step' => $exception->step,
                'error_code' => $exception->errorCode,
            ]);

            throw $exception;
        }

        $rule->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return [
            'rule' => $rule->refresh()->load('node'),
            'created' => $created,
            'backend_status' => $backendStatus,
        ];
    }

    private function backendInactive(Node $node): FirewallOperationException
    {
        return new FirewallOperationException(
            step: 'status',
            errorCode: 'firewall.backend_inactive',
            message: "UFW is inactive on node [{$node->name}].",
            status: 503,
        );
    }

    /** @param array{action: FirewallAction, source: string, protocol: string, port: string} $attributes */
    private function matches(FirewallRule $rule, array $attributes): bool
    {
        return (
            $rule->action === $attributes['action']
            && $rule->source === $attributes['source']
            && $rule->protocol === $attributes['protocol']
            && $rule->port === $attributes['port']
        );
    }

    private function guardRecoverySsh(Node $node, StoreFirewallRuleData $data): void
    {
        if (
            $data->action !== FirewallAction::Deny
            || ! FirewallPort::contains($data->port, $node->public_ssh_port)
        ) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'firewall.public_ssh_deny_forbidden',
            message: "Firewall rule [{$data->name}] would deny the public recovery SSH port.",
        );
    }
}
