<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Processes\ProcessRuntime;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;

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
        'checkout_path' => '/home/orbit/apps/orbit/dev',
        'hostname' => 'dev.test',
        'certificate_mode' => CertificateMode::OrbitCa,
    ]);
    $workspace = Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'feature',
        'branch' => 'feature/test',
        'checkout_path' => '/home/orbit/apps/orbit/dev/.worktrees/feature',
        'hostname' => 'feature.dev.test',
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
