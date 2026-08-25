<?php

declare(strict_types=1);

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;

describe(ProvisionNodeAction::class, function (): void {
    it('activates a node after its requested roles converge', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node): void {}
        });

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
        ));

        expect($node->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active);
    });

    it('stores the failed step and stable error code', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node): void
            {
                throw new NodeProvisioningException('base-packages', 'node.package_install_failed', 'Apt failed.');
            }
        });
        $action = app(ProvisionNodeAction::class);
        $data = new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
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
