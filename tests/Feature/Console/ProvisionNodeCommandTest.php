<?php

declare(strict_types=1);

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Models\Node;

it('provisions the first peer from the gateway console', function (): void {
    app()->instance(PrivateDnsManager::class, new class implements PrivateDnsManager {
        public function converge(?Node $pendingNode = null): void {}
    });
    app()->instance(NodeConverger::class, new class implements NodeConverger {
        public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
    });

    $this
        ->artisan('orbit:node-provision', [
            'name' => 'operator',
            'host' => '94.237.108.25',
            '--role' => ['app-dev'],
            '--platform' => 'linux',
            '--architecture' => 'x86_64',
            '--tld' => '.Operator.Orbit',
            '--wireguard-address' => '10.44.0.2',
            '--wireguard-endpoint' => '10.0.0.2:51820',
            '--dns-server' => '10.0.0.2',
            '--host-key-fingerprint' => 'SHA256:pinned',
        ])
        ->expectsOutputToContain('Node [operator] is active.')
        ->assertExitCode(0);

    $node = Node::query()->where('name', 'operator')->sole();

    expect($node->platform)
        ->toBe('linux')
        ->and($node->architecture)
        ->toBe('x86_64')
        ->and($node->tld)
        ->toBe('operator.orbit');
});
