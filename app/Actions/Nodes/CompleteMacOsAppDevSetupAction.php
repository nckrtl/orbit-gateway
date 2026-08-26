<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\MacOsAppDevSetupResultData;
use App\Domain\MacOs\MacOsAppDevVerifier;
use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;
use App\Models\NodeRole;
use Throwable;

final readonly class CompleteMacOsAppDevSetupAction
{
    /** @var list<string> */
    private const array RETRYABLE_ERROR_CODES = [
        'macos.setup_failed',
        'node.unreachable',
        'macos.verification_failed',
    ];

    public function __construct(
        private MacOsAppDevVerifier $verifier,
    ) {}

    public function execute(Node $node, MacOsAppDevSetupResultData $result): NodeRole
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

        if (
            $node->status === LifecycleStatus::Failed
            && in_array(
                needle: $node->failed_step,
                haystack: ['wireguard-projection', 'private-dns'],
                strict: true,
            )
        ) {
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
            && ! in_array(
                needle: $assignment->error_code,
                haystack: self::RETRYABLE_ERROR_CODES,
                strict: true,
            )
        ) {
            throw new ResourceOperationException(
                errorCode: 'node.role_setup_not_ready',
                message: 'The app-dev role setup is not eligible for retry.',
                status: 409,
            );
        }

        if ($result->exitCode !== 0) {
            $this->markFailed($node, $assignment, 'macos.setup_failed');

            throw new ResourceOperationException(
                errorCode: 'macos.setup_failed',
                message: 'The local macOS app-dev setup failed.',
                status: 422,
                safeDetails: ['failed_step' => 'local-setup'],
            );
        }

        try {
            $this->verifier->verify($node);
        } catch (MacOsProtectedDriftException $exception) {
            throw $exception;
        } catch (ResourceOperationException $exception) {
            $this->markFailed($node, $assignment, $exception->errorCode);

            throw $exception;
        } catch (Throwable) {
            $this->markFailed($node, $assignment, 'macos.verification_failed');

            throw new ResourceOperationException(
                errorCode: 'macos.verification_failed',
                message: 'The live macOS app-dev verification failed.',
                status: 502,
            );
        }

        $active = [
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ];
        $node->update($active);
        $assignment->update($active);

        return $assignment->refresh()->load('node');
    }

    private function markFailed(Node $node, NodeRole $assignment, string $errorCode): void
    {
        $failed = [
            'status' => LifecycleStatus::Failed,
            'failed_step' => 'local-setup',
            'error_code' => $errorCode,
        ];
        $node->update($failed);
        $assignment->update($failed);
    }
}
