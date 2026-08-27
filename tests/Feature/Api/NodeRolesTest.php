<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeRoleDependencySet;
use App\Domain\Nodes\NodeRoleDependentCleaner;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;

beforeEach(function (): void {
    $this->roleLifecycle = new NodeRoleApiLifecycleFake;
    app()->instance(RoleBaselineConverger::class, $this->roleLifecycle);
    app()->instance(NodeRoleDependentCleaner::class, $this->roleLifecycle);

    $this->caller = $this->markAsGateway(node_roles_api_node('gateway-peer'));
    $this->node = node_roles_api_node('role-target');
    $this->withServerVariables(['REMOTE_ADDR' => $this->caller->wireguard_address]);
});

it('exposes only the exact numeric node role routes and methods', function (): void {
    $routes = collect(app('router')->getRoutes()->getRoutes())
        ->filter(static fn (\Illuminate\Routing\Route $route): bool => str_starts_with(
            (string) $route->getName(),
            'node:role:',
        ))
        ->mapWithKeys(static fn (\Illuminate\Routing\Route $route): array => [
            $route->getName() => [
                'uri' => $route->uri(),
                'methods' => $route->methods(),
                'node_where' => $route->wheres['node'] ?? null,
            ],
        ])
        ->all();

    expect($routes)->toBe([
        'node:role:list' => [
            'uri' => 'api/v1/nodes/{node}/roles',
            'methods' => ['GET', 'HEAD'],
            'node_where' => '[0-9]+',
        ],
        'node:role:add' => [
            'uri' => 'api/v1/nodes/{node}/roles',
            'methods' => ['POST'],
            'node_where' => '[0-9]+',
        ],
        'node:role:remove' => [
            'uri' => 'api/v1/nodes/{node}/roles/{role}',
            'methods' => ['DELETE'],
            'node_where' => '[0-9]+',
        ],
    ]);
});

it('lists assignments in role catalog order with the stable projection', function (): void {
    $appProd = $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppProd,
            'status' => LifecycleStatus::Failed,
            'failed_step' => 'converge:packages',
            'error_code' => 'packages.failed',
        ]);
    $vpn = $this->node
        ->roles()
        ->create([
            'role' => RoleName::Vpn,
            'status' => LifecycleStatus::Active,
        ]);
    $appDev = $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
    $requestId = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson("/api/v1/nodes/{$this->node->id}/roles")
        ->assertOk()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'data' => [
                [
                    'id' => $vpn->id,
                    'role' => 'vpn',
                    'status' => 'active',
                    'failed_step' => null,
                    'error_code' => null,
                ],
                [
                    'id' => $appDev->id,
                    'role' => 'app-dev',
                    'status' => 'active',
                    'failed_step' => null,
                    'error_code' => null,
                ],
                [
                    'id' => $appProd->id,
                    'role' => 'app-prod',
                    'status' => 'failed',
                    'failed_step' => 'converge:packages',
                    'error_code' => 'packages.failed',
                ],
            ],
            'meta' => ['request_id' => $requestId],
        ]);
});

it('returns 201 for a new assignment and 200 for explicit convergence', function (): void {
    $requestId = (string) Str::uuid();

    $created = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson("/api/v1/nodes/{$this->node->id}/roles", [
            'role' => 'app-dev',
            'converge_existing' => false,
        ]);
    $assignment = NodeRole::query()->where('node_id', $this->node->id)->sole();

    $created
        ->assertCreated()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'data' => [
                'node_id' => $this->node->id,
                'node_name' => $this->node->name,
                'role' => 'app-dev',
                'assignment' => [
                    'id' => $assignment->id,
                    'role' => 'app-dev',
                    'status' => 'active',
                    'failed_step' => null,
                    'error_code' => null,
                ],
                'removed' => false,
            ],
            'meta' => ['request_id' => $requestId],
        ]);

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson("/api/v1/nodes/{$this->node->id}/roles", [
            'role' => 'app-dev',
            'converge_existing' => true,
        ])
        ->assertOk()
        ->assertJsonPath('data.assignment.id', $assignment->id)
        ->assertJsonPath('data.removed', false)
        ->assertJsonPath('meta.request_id', $requestId);

    expect($this->roleLifecycle->converged)->toBe(['app-dev', 'app-dev']);
});

it('returns standard validation failures for protected unknown and duplicate assignments', function (
    string $role,
    string $fixture,
): void {
    if ($fixture === 'preassigned') {
        $this->node
            ->roles()
            ->create([
                'role' => RoleName::AppDev,
                'status' => LifecycleStatus::Active,
            ]);
    }

    $response = $this->postJson("/api/v1/nodes/{$this->node->id}/roles", [
        'role' => $role,
        'converge_existing' => false,
    ]);

    $response
        ->assertUnprocessable()
        ->assertHeader('X-Orbit-Request-Id')
        ->assertJsonPath('error.code', 'validation.failed');

    expect($response->getContent())
        ->not
        ->toContain('trace', 'stdout', 'stderr')
        ->and($this->roleLifecycle->converged)
        ->toBeEmpty();
})->with([
    'gateway is protected' => ['gateway', 'unassigned'],
    'vpn is protected' => ['vpn', 'unassigned'],
    'unknown role' => ['future-role', 'unassigned'],
    'existing role requires explicit convergence' => ['app-dev', 'preassigned'],
]);

it('always returns the exact preview without mutating when force is absent or false', function (
    array $body,
): void {
    $assignment = $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
    $requestId = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->deleteJson("/api/v1/nodes/{$this->node->id}/roles/app-dev", $body)
        ->assertUnprocessable()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'error' => [
                'code' => 'validation.failed',
                'message' => 'Use --force to remove this node role.',
                'details' => [
                    'field' => 'force',
                    'reason' => 'destructive_consent_required',
                    'role' => 'app-dev',
                    'dependents' => [],
                ],
            ],
        ]);

    expect($assignment->refresh()->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->roleLifecycle->removed)
        ->toBeEmpty();
})->with([
    'absent force' => [['purge_data' => false]],
    'explicit false' => [['force' => false]],
]);

it('returns the exact mutation snapshot and forwards purge data on confirmed removal', function (): void {
    $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
    $requestId = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->deleteJson("/api/v1/nodes/{$this->node->id}/roles/app-dev", [
            'force' => true,
            'purge_data' => true,
        ])
        ->assertOk()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'data' => [
                'node_id' => $this->node->id,
                'node_name' => $this->node->name,
                'role' => 'app-dev',
                'assignment' => null,
                'removed' => true,
            ],
            'meta' => ['request_id' => $requestId],
        ]);

    expect(NodeRole::query()->where('node_id', $this->node->id)->count())
        ->toBe(0)
        ->and($this->roleLifecycle->removed)
        ->toBe([['role' => 'app-dev', 'purge_data' => true]]);
});

it('requires force when purge data is true before the removal action runs', function (): void {
    $assignment = $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);

    $this
        ->deleteJson("/api/v1/nodes/{$this->node->id}/roles/app-dev", [
            'force' => false,
            'purge_data' => true,
        ])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed')
        ->assertJsonPath('error.details.force.0', 'The force field must be true when purge data is requested.');

    expect($assignment->refresh()->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->roleLifecycle->removed)
        ->toBeEmpty();
});

it('requires active peer identity and direct target access for all role routes', function (): void {
    $direct = node_roles_api_node('direct-peer');
    $direct->accessibleNodes()->attach($this->node);

    $this
        ->withServerVariables(['REMOTE_ADDR' => $direct->wireguard_address])
        ->getJson("/api/v1/nodes/{$this->node->id}/roles")
        ->assertOk();

    $denied = node_roles_api_node('denied-peer');

    $this
        ->withServerVariables(['REMOTE_ADDR' => $denied->wireguard_address])
        ->getJson("/api/v1/nodes/{$this->node->id}/roles")
        ->assertForbidden()
        ->assertJsonPath('error.code', 'node_access.required');

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.99.99'])
        ->getJson("/api/v1/nodes/{$this->node->id}/roles")
        ->assertForbidden()
        ->assertJsonPath('error.code', 'peer.identity_unknown');
});

it('returns safe binding and inactive-node failures', function (): void {
    $inactive = node_roles_api_node('inactive-target', LifecycleStatus::Failed);

    $this
        ->getJson('/api/v1/nodes/999999/roles')
        ->assertNotFound()
        ->assertJsonPath('error.code', 'http.404');
    $this
        ->getJson('/api/v1/nodes/not-numeric/roles')
        ->assertNotFound()
        ->assertJsonPath('error.code', 'http.404');
    $this
        ->postJson("/api/v1/nodes/{$inactive->id}/roles", ['role' => 'app-dev'])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');
});

it('returns a safe correlated 502 for convergence failure', function (): void {
    $sentinel = (string) Str::uuid();
    $requestId = (string) Str::uuid();
    $this->roleLifecycle->convergenceFailure = new NodeRoleOperationException(
        step: 'packages',
        errorCode: 'node_role.convergence_failed',
        underlyingErrorCode: 'packages.failed',
        message: 'Role convergence failed.',
        result: new CommandResult(23, $sentinel, $sentinel, 10, false),
    );

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson("/api/v1/nodes/{$this->node->id}/roles", ['role' => 'app-dev']);

    $response
        ->assertStatus(502)
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'error' => [
                'code' => 'node_role.convergence_failed',
                'message' => 'Role convergence failed.',
                'details' => ['step' => 'converge:packages'],
            ],
        ]);

    expect($response->getContent())
        ->not
        ->toContain($sentinel)
        ->and(Activity::query()->where('request_id', $requestId)->sole()->error_code)
        ->toBe('node_role.convergence_failed');
});

it('returns a safe correlated 502 for removal failure', function (): void {
    $sentinel = (string) Str::uuid();
    $requestId = (string) Str::uuid();
    $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
    $this->roleLifecycle->removalFailure = new NodeRoleOperationException(
        step: 'firewall',
        errorCode: 'node_role.remove_failed',
        underlyingErrorCode: 'firewall.failed',
        message: 'Role removal failed.',
        result: new CommandResult(24, $sentinel, $sentinel, 11, false),
    );

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->deleteJson("/api/v1/nodes/{$this->node->id}/roles/app-dev", [
            'force' => true,
            'purge_data' => false,
        ]);

    $response
        ->assertStatus(502)
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertExactJson([
            'error' => [
                'code' => 'node_role.remove_failed',
                'message' => 'Role removal failed.',
                'details' => ['step' => 'remove:firewall'],
            ],
        ]);

    expect($response->getContent())
        ->not
        ->toContain($sentinel)
        ->and(Activity::query()->where('request_id', $requestId)->sole()->error_code)
        ->toBe('node_role.remove_failed');
});

it('rejects unsafe raw JSON without mutation or rejected activity input', function (
    string $method,
    string $path,
    string $json,
): void {
    $requestId = (string) Str::uuid();
    $sentinel = 'rejected-raw-sentinel';

    if ($method === 'DELETE') {
        $this->node
            ->roles()
            ->create([
                'role' => RoleName::AppDev,
                'status' => LifecycleStatus::Active,
            ]);
    }

    $response = node_roles_raw_json(
        test: $this,
        method: $method,
        uri: str_replace('{node}', (string) $this->node->id, $path),
        json: str_replace('{sentinel}', $sentinel, $json),
        remoteAddress: (string) $this->caller->wireguard_address,
        requestId: $requestId,
    );

    $response
        ->assertUnprocessable()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertJsonPath('error.code', 'validation.failed');

    $activity = Activity::query()->where('request_id', $requestId)->sole();

    expect($response->getContent())
        ->not->toContain($sentinel)->and(json_encode($activity->properties?->toArray()))
        ->not->toContain(
            $sentinel,
        )->and($this->roleLifecycle->converged)->toBeEmpty()->and($this->roleLifecycle->removed)->toBeEmpty();
})->with([
    'duplicate key' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"app-dev","role":"{sentinel}"}',
    ],
    'escaped duplicate key' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"app-dev","r\\u006fle":"{sentinel}"}',
    ],
    'unknown key' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"app-dev","unknown":"{sentinel}"}',
    ],
    'unknown role' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"{sentinel}","converge_existing":false}',
    ],
    'malformed JSON' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"app-dev","unknown":"{sentinel}"',
    ],
    'non-boolean add flag' => [
        'POST',
        '/api/v1/nodes/{node}/roles',
        '{"role":"app-dev","converge_existing":"{sentinel}"}',
    ],
    'non-boolean remove flag' => [
        'DELETE',
        '/api/v1/nodes/{node}/roles/app-dev',
        '{"force":"{sentinel}","purge_data":false}',
    ],
]);

/** @mago-expect lint:excessive-parameter-list Test transport helper preserves exact raw JSON. */
function node_roles_raw_json(
    Tests\TestCase $test,
    string $method,
    string $uri,
    string $json,
    string $remoteAddress,
    string $requestId,
): TestResponse {
    return $test->call(
        $method,
        $uri,
        server: [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_X_ORBIT_REQUEST_ID' => $requestId,
            'REMOTE_ADDR' => $remoteAddress,
        ],
        content: $json,
    );
}

function node_roles_api_node(
    string $name,
    LifecycleStatus $status = LifecycleStatus::Active,
): Node {
    return Node::query()->create([
        'name' => $name,
        'status' => $status,
        'platform' => 'linux',
        'public_ssh_host' => $name.'.example.test',
        'wireguard_address' => '10.44.10.'.(Node::query()->count() + 2),
    ]);
}

/** @mago-expect lint:file-name Test-local fake isolates all remote role effects. */
final class NodeRoleApiLifecycleFake implements RoleBaselineConverger, NodeRoleDependentCleaner
{
    /** @var list<string> */
    public array $converged = [];

    /** @var list<array{role: string, purge_data: bool}> */
    public array $removed = [];

    public ?NodeRoleOperationException $convergenceFailure = null;

    public ?NodeRoleOperationException $removalFailure = null;

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->converged[] = $assignment->role->value;

        if ($this->convergenceFailure instanceof NodeRoleOperationException) {
            throw $this->convergenceFailure;
        }
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void
    {
        $this->removed[] = [
            'role' => $assignment->role->value,
            'purge_data' => $purgeData,
        ];

        if ($this->removalFailure instanceof NodeRoleOperationException) {
            throw $this->removalFailure;
        }
    }

    public function clean(NodeRoleDependencySet $dependencies): void {}
}
