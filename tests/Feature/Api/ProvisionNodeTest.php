<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Str;

describe('POST /api/v1/nodes', function (): void {
    it('provisions a node through the gateway action', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node): void {}
        });
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'public_ssh_host' => '94.237.40.75',
                'roles' => ['app-dev'],
                'wireguard_endpoint_override' => '10.0.0.2:51820',
                'dns_server_override' => '10.0.0.1',
            ])
            ->assertCreated()
            ->assertJsonPath('data.name', 'app-dev')
            ->assertJsonPath('data.status', 'active')
            ->assertJsonPath('data.roles.0', 'app-dev')
            ->assertJsonPath('meta.request_id', $requestId);

        expect(Activity::query()->where('request_id', $requestId)->sole()->command)
            ->toBe('node:provision');
    });

    it('returns the standard validation envelope and records rejection', function (): void {
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'not valid',
                'roles' => ['unknown'],
            ])
            ->assertUnprocessable()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('error.code', 'validation.failed')
            ->assertJsonStructure(['error' => ['code', 'message', 'details']]);

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->command)
            ->toBe('node:provision')
            ->and($activity->status)
            ->toBe('failed')
            ->and($activity->error_code)
            ->toBe('validation.failed');
    });

    it('records bounded native failure metadata', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node): void
            {
                throw new NodeProvisioningException(
                    step: 'base-host',
                    errorCode: 'node.bootstrap_failed',
                    message: 'Could not bootstrap the node.',
                    result: new CommandResult(12, 'partial', 'apt failed', 50, false),
                );
            }
        });
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'public_ssh_host' => '94.237.40.75',
                'roles' => ['app-dev'],
            ])
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'node.bootstrap_failed')
            ->assertJsonPath('error.details.step', 'base-host');

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->exit_code)
            ->toBe(12)
            ->and($activity->properties?->get('stdout'))
            ->toBe('partial')
            ->and($activity->properties?->get('stderr'))
            ->toBe('apt failed');
    });
});
