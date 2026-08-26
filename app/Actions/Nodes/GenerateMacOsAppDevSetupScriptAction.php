<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Data\Nodes\MacOsAppDevSetupScriptData;
use App\Domain\MacOs\MacOsAppDevSetupRenderer;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class GenerateMacOsAppDevSetupScriptAction
{
    /** @var list<string> */
    private const array RETRYABLE_ERROR_CODES = [
        'macos.setup_failed',
        'node.unreachable',
        'macos.verification_failed',
    ];

    public function __construct(
        private MacOsAppDevSetupRenderer $renderer,
    ) {}

    public function execute(Node $node, MacOsAppDevSetupFactsData $facts): MacOsAppDevSetupScriptData
    {
        $assignment = $node->roles()->where('role', RoleName::AppDev->value)->first();

        if (! $assignment instanceof NodeRole) {
            throw new ResourceOperationException(
                errorCode: 'node.role_setup_not_assigned',
                message: 'The caller does not have the app-dev role.',
                status: 409,
            );
        }

        if ($assignment->status === LifecycleStatus::Active) {
            throw new ResourceOperationException(
                errorCode: 'node.role_setup_not_required',
                message: 'The app-dev role setup is already complete.',
                status: 409,
            );
        }

        if ($this->enrollmentFailed($node)) {
            throw new ResourceOperationException(
                errorCode: 'node.role_setup_not_ready',
                message: 'The app-dev role enrollment projections are not ready.',
                status: 409,
                safeDetails: [
                    'failed_step' => $node->failed_step,
                    'local_action_required' => false,
                    'local_command' => null,
                ],
            );
        }

        if (
            $assignment->status === LifecycleStatus::Failed
            && ! in_array(needle: $assignment->error_code, haystack: self::RETRYABLE_ERROR_CODES, strict: true)
        ) {
            throw new ResourceOperationException(
                errorCode: 'node.role_setup_not_ready',
                message: 'The app-dev role setup is not eligible for retry.',
                status: 409,
                safeDetails: [
                    'failed_step' => null,
                    'local_action_required' => false,
                    'local_command' => null,
                ],
            );
        }

        if ($assignment->status === LifecycleStatus::Failed) {
            $this->resetSetupFailure($node, $assignment);
        }

        $plan = $this->renderer->render($node, $assignment, $facts);

        if (strlen($plan->summary) > 4_096 || strlen($plan->script) > 262_144) {
            throw new ResourceOperationException(
                errorCode: 'gateway.invalid_setup_plan',
                message: 'The generated setup plan exceeds its transport bounds.',
                status: 500,
            );
        }

        return new MacOsAppDevSetupScriptData(
            role: RoleName::AppDev->value,
            summary: $plan->summary,
            script: $plan->script,
        );
    }

    private function enrollmentFailed(Node $node): bool
    {
        return (
            $node->status === LifecycleStatus::Failed
            && in_array(
                needle: $node->failed_step,
                haystack: ['wireguard-projection', 'private-dns'],
                strict: true,
            )
        );
    }

    private function resetSetupFailure(Node $node, NodeRole $assignment): void
    {
        $state = [
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ];
        $node->update($state);
        $assignment->update($state);
    }
}
