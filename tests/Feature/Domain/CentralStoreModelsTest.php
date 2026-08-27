<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Tools\ToolManagerName;
use App\Domain\Tools\ToolStatus;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\NodeAccess;
use App\Models\Process;
use App\Models\Workspace;
use Illuminate\Database\QueryException;

it('stores apps, instances, workspaces, and their process ownership', function (): void {
    $node = Node::query()->create([
        'name' => 'app-dev',
        'public_ssh_host' => '94.237.40.75',
    ]);
    $app = OrbitApp::query()->create([
        'name' => 'Orbit',
        'slug' => 'orbit',
        'repository_url' => 'git@github.com:nckrtl/orbit.git',
    ]);
    $instance = Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'dev',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/orbit',
        'hostname' => 'orbit.test',
        'certificate_mode' => CertificateMode::OrbitCa,
    ]);
    $workspace = Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'feature',
        'branch' => 'feature/test',
        'checkout_path' => '/home/orbit/.orbit/worktrees/orbit/feature',
        'hostname' => 'feature.orbit.test',
    ]);
    $process = $workspace
        ->processes()
        ->create([
            'name' => 'vite',
            'runtime' => ProcessRuntime::Systemd,
            'working_directory' => $workspace->checkout_path,
            'runtime_config' => ['command' => 'npm run dev'],
        ]);

    expect($app->instances()->sole()->is($instance))
        ->toBeTrue()
        ->and($node->instances()->sole()->is($instance))
        ->toBeTrue()
        ->and($instance->workspaces()->sole()->is($workspace))
        ->toBeTrue()
        ->and($process)
        ->toBeInstanceOf(Process::class)
        ->and($process->owner->is($workspace))
        ->toBeTrue();
});

it('enforces at most one app instance on each node', function (): void {
    $node = Node::query()->create([
        'name' => 'app-dev',
        'public_ssh_host' => '94.237.40.75',
    ]);
    $app = OrbitApp::query()->create([
        'name' => 'Orbit',
        'slug' => 'orbit',
        'repository_url' => 'git@github.com:nckrtl/orbit.git',
    ]);
    Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'first',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/orbit',
        'hostname' => 'orbit.test',
        'certificate_mode' => CertificateMode::OrbitCa,
    ]);

    expect(fn () => Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'second',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/orbit',
        'hostname' => 'other.test',
        'certificate_mode' => CertificateMode::OrbitCa,
    ]))
        ->toThrow(QueryException::class);
});

describe('node access persistence', function (): void {
    it('stores directed access between consumer and serving nodes', function (): void {
        $consumer = Node::query()->create([
            'name' => 'consumer',
            'public_ssh_host' => '192.0.2.10',
        ]);
        $serving = Node::query()->create([
            'name' => 'serving',
            'public_ssh_host' => '192.0.2.11',
        ]);

        $consumer->accessibleNodes()->attach($serving);

        expect($consumer->accessibleNodes()->sole()->is($serving))
            ->toBeTrue()
            ->and($serving->accessingNodes()->sole()->is($consumer))
            ->toBeTrue()
            ->and($consumer->accessingNodes()->exists())
            ->toBeFalse()
            ->and($serving->accessibleNodes()->exists())
            ->toBeFalse();
    });

    it('rejects duplicate directed access pairs', function (): void {
        $consumer = Node::query()->create([
            'name' => 'consumer',
            'public_ssh_host' => '192.0.2.10',
        ]);
        $serving = Node::query()->create([
            'name' => 'serving',
            'public_ssh_host' => '192.0.2.11',
        ]);
        $access = NodeAccess::query()->create([
            'consumer_node_id' => $consumer->id,
            'serving_node_id' => $serving->id,
        ]);

        expect($access->consumer)
            ->toBeInstanceOf(Node::class)
            ->and($access->consumer->is($consumer))
            ->toBeTrue()
            ->and($access->serving)
            ->toBeInstanceOf(Node::class)
            ->and($access->serving->is($serving))
            ->toBeTrue();

        expect(fn () => NodeAccess::query()->create([
            'consumer_node_id' => $consumer->id,
            'serving_node_id' => $serving->id,
        ]))
            ->toThrow(QueryException::class);
    });

    it('removes access rows when the consumer node is deleted', function (): void {
        $consumer = Node::query()->create([
            'name' => 'consumer',
            'public_ssh_host' => '192.0.2.10',
        ]);
        $firstServing = Node::query()->create([
            'name' => 'first-serving',
            'public_ssh_host' => '192.0.2.11',
        ]);
        $secondServing = Node::query()->create([
            'name' => 'second-serving',
            'public_ssh_host' => '192.0.2.12',
        ]);
        $consumer->accessibleNodes()->attach([$firstServing->id, $secondServing->id]);

        $consumer->delete();

        $this->assertDatabaseMissing('node_access', [
            'consumer_node_id' => $consumer->id,
        ]);
    });

    it('removes access rows when the serving node is deleted', function (): void {
        $firstConsumer = Node::query()->create([
            'name' => 'first-consumer',
            'public_ssh_host' => '192.0.2.10',
        ]);
        $secondConsumer = Node::query()->create([
            'name' => 'second-consumer',
            'public_ssh_host' => '192.0.2.11',
        ]);
        $serving = Node::query()->create([
            'name' => 'serving',
            'public_ssh_host' => '192.0.2.12',
        ]);
        $firstConsumer->accessibleNodes()->attach($serving);
        $secondConsumer->accessibleNodes()->attach($serving);

        $serving->delete();

        $this->assertDatabaseMissing('node_access', [
            'serving_node_id' => $serving->id,
        ]);
    });
});

it('stores one tracked tool manager and package identity per node', function (): void {
    $node = Node::query()->create([
        'name' => 'tools-node',
        'public_ssh_host' => '192.0.2.80',
    ]);
    $manager = $node->toolManagers()->create([
        'name' => ToolManagerName::Vp,
        'status' => LifecycleStatus::Active,
        'installed_version' => '0.2.6',
    ]);
    $tool = $node->tools()->create([
        'tool_manager_id' => $manager->id,
        'package' => '@openai/codex',
        'version_constraint' => '^0.150',
        'status' => ToolStatus::Installed,
        'installed_version' => '0.150.0',
    ]);

    expect($manager->node->is($node))
        ->toBeTrue()
        ->and($manager->tools()->sole()->is($tool))
        ->toBeTrue()
        ->and($tool->node->is($node))
        ->toBeTrue()
        ->and($tool->manager->is($manager))
        ->toBeTrue()
        ->and($tool->protected)
        ->toBeFalse()
        ->and($tool->failed_operation)
        ->toBeNull();
});

it('enforces manager and tool identity uniqueness', function (): void {
    $node = Node::query()->create([
        'name' => 'unique-tools-node',
        'public_ssh_host' => '192.0.2.81',
    ]);
    $manager = $node->toolManagers()->create([
        'name' => ToolManagerName::Apt,
        'status' => LifecycleStatus::Active,
    ]);
    $node->tools()->create([
        'tool_manager_id' => $manager->id,
        'package' => 'jq',
        'status' => ToolStatus::Installed,
    ]);

    expect(fn () => $node->toolManagers()->create([
        'name' => ToolManagerName::Apt,
        'status' => LifecycleStatus::Active,
    ]))
        ->toThrow(QueryException::class)
        ->and(fn () => $node->tools()->create([
            'tool_manager_id' => $manager->id,
            'package' => 'jq',
            'status' => ToolStatus::Installed,
        ]))
        ->toThrow(QueryException::class);
});
