<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeConverger;
use App\Models\Node;

it('provisions the first peer from the gateway console', function (): void {
    app()->instance(NodeConverger::class, new class implements NodeConverger {
        public function converge(Node $node): void {}
    });

    $this
        ->artisan('orbit:node-provision', [
            'name' => 'operator',
            'host' => '94.237.108.25',
            '--role' => ['app-dev'],
            '--wireguard-address' => '10.44.0.2',
            '--wireguard-endpoint' => '10.0.0.2:51820',
            '--dns-server' => '10.0.0.2',
        ])
        ->expectsOutputToContain('Node [operator] is active.')
        ->assertExitCode(0);
});
