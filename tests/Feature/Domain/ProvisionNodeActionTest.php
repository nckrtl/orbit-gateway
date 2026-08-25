<?php

declare(strict_types=1);

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;

describe(ProvisionNodeAction::class, function (): void {
    it('activates a node after its requested roles converge', function (): void {
        $converger = new class implements NodeConverger {
            public ?string $expectedFingerprint = null;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            expectedSshHostFingerprint: 'SHA256:pinned',
        ));

        expect($node->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($converger->expectedFingerprint)
            ->toBe('SHA256:pinned');
    });

    it('requires a first-contact fingerprint before persisting a node', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.ssh_host_fingerprint_required');
        });

        expect(Node::query()->where('name', 'app-dev')->exists())
            ->toBeFalse()
            ->and($converger->calls)
            ->toBe(0);
    });

    it('stores the failed step and stable error code', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                throw new NodeProvisioningException('base-packages', 'node.package_install_failed', 'Apt failed.');
            }
        });
        $action = app(ProvisionNodeAction::class);
        $data = new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            expectedSshHostFingerprint: 'SHA256:pinned',
        );

        expect(fn () => $action->execute($data))->toThrow(NodeProvisioningException::class, 'Apt failed.');

        $node = Node::query()->where('name', 'app-dev')->sole();

        expect($node->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->failed_step)
            ->toBe('base-packages')
            ->and($node->error_code)
            ->toBe('node.package_install_failed');
    });
});
