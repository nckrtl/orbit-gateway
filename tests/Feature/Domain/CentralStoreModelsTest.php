<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Processes\ProcessRuntime;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
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
