<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\NodeRoleDependencyInspector;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Nodes\EloquentNodeRoleDependencyInspector;
use App\Models\App;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;

describe(EloquentNodeRoleDependencyInspector::class, function (): void {
    it('returns deterministic app-dev dependencies from certificate ownership across every lifecycle state', function (): void {
        $node = dependency_node('dependency-dev');
        $development = dependency_instance(
            node: $node,
            slug: 'development-owned',
            certificateMode: CertificateMode::OrbitCa,
            environment: 'production',
            status: LifecycleStatus::Failed,
        );
        dependency_instance(
            node: $node,
            slug: 'wrong-runtime',
            certificateMode: CertificateMode::Acme,
            environment: 'development',
        );
        $workspaceTwo = dependency_workspace(instance: $development, name: 'two', status: LifecycleStatus::Removing);
        $workspaceOne = dependency_workspace(instance: $development, name: 'one', status: LifecycleStatus::Failed);
        $workspaceProcess = dependency_process(
            owner: $workspaceTwo,
            name: 'workspace',
            status: LifecycleStatus::Removing,
        );
        $instanceProcess = dependency_process(owner: $development, name: 'instance', status: LifecycleStatus::Failed);

        $dependencies = app(NodeRoleDependencyInspector::class)->inspect($node, RoleName::AppDev);

        expect($dependencies->instanceIds)
            ->toBe([$development->id])
            ->and($dependencies->workspaceIds)
            ->toBe([$workspaceTwo->id, $workspaceOne->id])
            ->and($dependencies->processIds)
            ->toBe([$workspaceProcess->id, $instanceProcess->id])
            ->and($dependencies->summaries)
            ->toBe([
                '1 development instance record',
                '2 process records',
                '2 workspace records',
            ]);
    });

    it('returns only ACME instance-owned dependencies for app-prod regardless of environment labels', function (): void {
        $node = dependency_node('dependency-prod');
        $production = dependency_instance(
            node: $node,
            slug: 'production-owned',
            certificateMode: CertificateMode::Acme,
            environment: 'development',
            status: LifecycleStatus::Removing,
        );
        $workspace = dependency_workspace(
            instance: $production,
            name: 'ignored-workspace',
            status: LifecycleStatus::Active,
        );
        $directProcess = dependency_process(owner: $production, name: 'direct', status: LifecycleStatus::Provisioning);
        dependency_process(owner: $workspace, name: 'nested-ignored', status: LifecycleStatus::Active);

        $dependencies = app(NodeRoleDependencyInspector::class)->inspect($node, RoleName::AppProd);

        expect($dependencies->instanceIds)
            ->toBe([$production->id])
            ->and($dependencies->workspaceIds)
            ->toBeEmpty()
            ->and($dependencies->processIds)
            ->toBe([$directProcess->id])
            ->and($dependencies->summaries)
            ->toBe([
                '1 process record',
                '1 production instance record',
            ]);
    });

    it('returns an empty deterministic set for roles without application dependents', function (): void {
        $dependencies = app(NodeRoleDependencyInspector::class)->inspect(
            dependency_node('dependency-empty'),
            RoleName::Gateway,
        );

        expect($dependencies->instanceIds)
            ->toBeEmpty()
            ->and($dependencies->workspaceIds)
            ->toBeEmpty()
            ->and($dependencies->processIds)
            ->toBeEmpty()
            ->and($dependencies->summaries)
            ->toBeEmpty();
    });
});

function dependency_node(string $name): Node
{
    return Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.90',
    ]);
}

function dependency_instance(
    Node $node,
    string $slug,
    CertificateMode $certificateMode,
    string $environment,
    LifecycleStatus $status = LifecycleStatus::Active,
): Instance {
    $app = App::query()->create([
        'name' => ucfirst($slug),
        'slug' => $slug,
        'repository_url' => "git@example.test:{$slug}.git",
    ]);

    return Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'main',
        'environment' => $environment,
        'checkout_path' => "/srv/{$slug}",
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => "{$slug}.example.test",
        'certificate_mode' => $certificateMode,
        'status' => $status,
    ]);
}

function dependency_workspace(Instance $instance, string $name, LifecycleStatus $status): Workspace
{
    return Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => $name,
        'branch' => $name,
        'checkout_path' => "{$instance->checkout_path}/{$name}",
        'hostname' => "{$name}.{$instance->hostname}",
        'status' => $status,
    ]);
}

function dependency_process(Instance|Workspace $owner, string $name, LifecycleStatus $status): Process
{
    return Process::query()->create([
        'owner_type' => $owner::class,
        'owner_id' => $owner->id,
        'name' => $name,
        'runtime' => 'systemd',
        'working_directory' => $owner->checkout_path,
        'runtime_config' => ['command' => ['/usr/bin/true']],
        'restart_policy' => 'never',
        'desired_state' => 'stopped',
        'status' => $status,
    ]);
}
