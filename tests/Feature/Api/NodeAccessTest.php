<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeAccess;

describe('node access API', function (): void {
    /** @mago-expect lint:halstead The API test keeps the full idempotent add/remove envelope visible in one flow. */
    it('lets an implicit Gateway peer add and remove node access idempotently', function (): void {
        $caller = $this->markAsGateway(node_access_api_node('gateway-peer'));
        $serving = node_access_api_node('app-dev');
        $consumer = node_access_api_node('operator');
        $requestId = '3a79c8ac-7d93-4eb3-bbf7-c53d63d55c11';

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertExactJson([
                'data' => [
                    'consumer_node' => ['id' => $consumer->id, 'name' => $consumer->name],
                    'serving_node' => ['id' => $serving->id, 'name' => $serving->name],
                    'already_exists' => false,
                ],
                'meta' => ['request_id' => $requestId],
            ]);

        expect(
            NodeAccess::query()
                ->where([
                    'consumer_node_id' => $consumer->id,
                    'serving_node_id' => $serving->id,
                ])
                ->count(),
        )
            ->toBe(1);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.already_exists', true)
            ->assertJsonPath('meta.request_id', $requestId);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertExactJson([
                'data' => [
                    'consumer_node' => ['id' => $consumer->id, 'name' => $consumer->name],
                    'serving_node' => ['id' => $serving->id, 'name' => $serving->name],
                    'already_absent' => false,
                    'self_lockout' => false,
                ],
                'meta' => ['request_id' => $requestId],
            ]);

        expect(NodeAccess::query()->count())->toBe(0);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.already_absent', true)
            ->assertJsonPath('data.self_lockout', false)
            ->assertJsonPath('meta.request_id', $requestId);
    });

    it('lets a peer with Gateway access add and remove node access', function (): void {
        $gateway = $this->markAsGateway(node_access_api_node('gateway'));
        $caller = node_access_api_node('gateway-access-consumer');
        $serving = node_access_api_node('serving');
        $consumer = node_access_api_node('consumer');
        $caller->accessibleNodes()->attach($gateway);
        $requestId = 'f9bd6e3f-9175-41e4-b342-fe964535c765';

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.already_exists', false)
            ->assertJsonPath('meta.request_id', $requestId);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.already_absent', false)
            ->assertJsonPath('data.self_lockout', false)
            ->assertJsonPath('meta.request_id', $requestId);
    });

    it('forbids a peer with direct access to only the serving node from managing access', function (): void {
        $caller = node_access_api_node('direct-only-caller');
        $serving = node_access_api_node('serving');
        $consumer = node_access_api_node('consumer');
        $caller->accessibleNodes()->attach($serving);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertForbidden()
            ->assertJsonPath('error.code', 'node_access.required');
    });

    it('forbids a peer with no effective access from managing access', function (): void {
        $caller = node_access_api_node('no-access-caller');
        $serving = node_access_api_node('serving');
        $consumer = node_access_api_node('consumer');

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
            ->assertForbidden()
            ->assertJsonPath('error.code', 'node_access.required');
    });

    it('accepts self-access add and reports self lockout when removing the caller gateway edge', function (): void {
        $gateway = $this->markAsGateway(node_access_api_node('gateway'));
        $caller = node_access_api_node('caller');
        $caller->accessibleNodes()->attach($gateway);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
            ->putJson("/api/v1/nodes/{$caller->id}/access/{$caller->id}")
            ->assertOk()
            ->assertJsonPath('data.already_exists', false);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->deleteJson("/api/v1/nodes/{$gateway->id}/access/{$caller->id}")
            ->assertOk()
            ->assertJsonPath('data.already_absent', false)
            ->assertJsonPath('data.self_lockout', true);
    });

    it('reports no self lockout when an absent self edge is removed', function (): void {
        $gateway = $this->markAsGateway(node_access_api_node('gateway'));
        $caller = node_access_api_node('caller');
        $caller->accessibleNodes()->attach($gateway);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->deleteJson("/api/v1/nodes/{$caller->id}/access/{$caller->id}")
            ->assertOk()
            ->assertJsonPath('data.already_absent', true)
            ->assertJsonPath('data.self_lockout', false);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
            ->deleteJson("/api/v1/nodes/{$gateway->id}/access/{$gateway->id}")
            ->assertOk()
            ->assertJsonPath('data.already_absent', true)
            ->assertJsonPath('data.self_lockout', false);
    });

    it('returns the existing 404 for missing or inactive serving and consumer nodes', function (): void {
        $caller = $this->markAsGateway(node_access_api_node('gateway-peer'));
        $serving = node_access_api_node('serving');
        $consumer = node_access_api_node('consumer');
        $inactiveServing = node_access_api_node('inactive-serving', status: LifecycleStatus::Failed);
        $inactiveConsumer = node_access_api_node('inactive-consumer', status: LifecycleStatus::Failed);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->putJson('/api/v1/nodes/999999/access/'.$consumer->id)
            ->assertNotFound()
            ->assertJsonPath('error.code', 'http.404');

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->putJson("/api/v1/nodes/{$serving->id}/access/999999")
            ->assertNotFound()
            ->assertJsonPath('error.code', 'http.404');

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->putJson("/api/v1/nodes/{$inactiveServing->id}/access/{$consumer->id}")
            ->assertNotFound()
            ->assertJsonPath('error.code', 'http.404');

        $this
            ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
            ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$inactiveConsumer->id}")
            ->assertNotFound()
            ->assertJsonPath('error.code', 'http.404');
    });
});

function node_access_api_node(
    string $name,
    LifecycleStatus $status = LifecycleStatus::Active,
): Node {
    return Node::query()->create([
        'name' => $name,
        'status' => $status,
        'public_ssh_host' => $name.'.example.test',
        'wireguard_address' => '10.44.0.'.(Node::query()->count() + 2),
    ]);
}
