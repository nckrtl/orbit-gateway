<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Shared\LifecycleStatus;
use App\Http\Authorization\ActiveGatewayMissing;
use App\Http\Authorization\ServingNode;
use App\Http\Authorization\ServingNodeResolver;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;

it('resolves the active Gateway node', function (): void {
    resolver_node('inactive-gateway', status: LifecycleStatus::Failed)
        ->roles()
        ->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);
    $gateway = resolver_node('gateway');
    $gateway->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);

    expect(resolver_node_ids(resolver()->resolve(resolver_request(), ServingNode::Gateway)))
        ->toBe([$gateway->id]);
});

it('fails closed when no node has an active Gateway role', function (string $topology): void {
    if ($topology === 'inactive node') {
        resolver_node('inactive-gateway', status: LifecycleStatus::Failed)
            ->roles()
            ->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);
    }

    if ($topology === 'inactive role') {
        resolver_node('inactive-role-gateway')
            ->roles()
            ->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Failed]);
    }

    resolver()->resolve(resolver_request(), ServingNode::Gateway);
})->with(['no Gateway', 'inactive node', 'inactive role'])->throws(ActiveGatewayMissing::class);

it('resolves target route models from both public parameter names', function (string $parameter): void {
    $target = resolver_node('target-'.$parameter);

    expect(resolver_node_ids(resolver()->resolve(resolver_request([$parameter => $target]), ServingNode::Target)))
        ->toBe([$target->id]);
})->with(['node', 'servingNode']);

it('resolves every distinct app-owning node in stable id order', function (): void {
    $app = resolver_app('multi-node-app');
    $first = resolver_node('first');
    $second = resolver_node('second');
    resolver_instance($app, $second, name: 'second');
    resolver_instance($app, $first, name: 'first');

    expect(resolver_node_ids(resolver()->resolve(resolver_request(['app' => $app]), ServingNode::AppOwning)))
        ->toBe([$first->id, $second->id]);
});

it('uses the active Gateway for an unplaced app', function (): void {
    $gateway = resolver_node('gateway');
    $gateway->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);
    $app = resolver_app('unplaced');

    expect(resolver_node_ids(resolver()->resolve(resolver_request(['app' => $app]), ServingNode::AppOwning)))
        ->toBe([$gateway->id]);
});

it('fails closed for an unplaced app without an active Gateway', function (): void {
    $app = resolver_app('unplaced-without-gateway');

    resolver()->resolve(resolver_request(['app' => $app]), ServingNode::AppOwning);
})->throws(ActiveGatewayMissing::class);

it('resolves an app-owning node from raw app input', function (): void {
    $app = resolver_app('raw-app');
    $node = resolver_node('raw-app-node');
    resolver_instance($app, $node, name: 'raw-app-instance');

    expect(resolver_node_ids(resolver()->resolve(
        resolver_request(input: ['app_id' => $app->id]),
        ServingNode::AppOwning,
    )))->toBe([$node->id]);
});

it('resolves instance-owning nodes from a bound instance and create input', function (): void {
    $app = resolver_app('instance-owner');
    $node = resolver_node('instance-node');
    $instance = resolver_instance($app, $node, name: 'instance');

    expect(resolver_node_ids(resolver()->resolve(
        resolver_request(['instance' => $instance]),
        ServingNode::InstanceOwning,
    )))
        ->toBe([$node->id])
        ->and(resolver_node_ids(resolver()->resolve(
            resolver_request(input: ['node_id' => $node->id]),
            ServingNode::InstanceOwning,
        )))
        ->toBe([$node->id]);
});

it('resolves workspace-owning nodes from a bound workspace and create input', function (): void {
    $app = resolver_app('workspace-owner');
    $node = resolver_node('workspace-node');
    $instance = resolver_instance($app, $node, name: 'workspace-instance');
    $workspace = resolver_workspace($instance, name: 'workspace');

    expect(resolver_node_ids(resolver()->resolve(
        resolver_request(['workspace' => $workspace]),
        ServingNode::WorkspaceOwning,
    )))
        ->toBe([$node->id])
        ->and(resolver_node_ids(resolver()->resolve(
            resolver_request(input: ['instance_id' => $instance->id]),
            ServingNode::WorkspaceOwning,
        )))
        ->toBe([$node->id]);
});

it('resolves process-owning nodes from bound and raw instance targets', function (): void {
    $app = resolver_app('process-owner');
    $node = resolver_node('process-node');
    $instance = resolver_instance($app, $node, name: 'process-instance');
    $process = resolver_process($instance);

    expect(resolver_node_ids(resolver()->resolve(
        resolver_request(['process' => $process]),
        ServingNode::ProcessOwning,
    )))
        ->toBe([$node->id])
        ->and(resolver_node_ids(resolver()->resolve(resolver_request(input: [
            'target_type' => 'instance',
            'target_id' => $instance->id,
        ]), ServingNode::ProcessOwning)))
        ->toBe([$node->id]);
});

it('resolves process-owning nodes from bound and raw workspace targets', function (): void {
    $app = resolver_app('workspace-process-owner');
    $node = resolver_node('workspace-process-node');
    $instance = resolver_instance($app, $node, name: 'workspace-process-instance');
    $workspace = resolver_workspace($instance, name: 'workspace-process');
    $process = resolver_process($workspace);

    expect(resolver_node_ids(resolver()->resolve(
        resolver_request(['process' => $process]),
        ServingNode::ProcessOwning,
    )))
        ->toBe([$node->id])
        ->and(resolver_node_ids(resolver()->resolve(resolver_request(input: [
            'target_type' => 'workspace',
            'target_id' => $workspace->id,
        ]), ServingNode::ProcessOwning)))
        ->toBe([$node->id]);
});

it('returns no concrete nodes for a collection', function (): void {
    expect(resolver()->resolve(resolver_request(), ServingNode::Collection))->toBeEmpty();
});

it('leaves malformed or absent raw identifiers to validation', function (string $scopeName, array $input): void {
    /** @var ServingNode $scope */
    $scope = constant(ServingNode::class.'::'.$scopeName);

    expect(resolver()->resolve(resolver_request(input: $input), $scope))->toBeEmpty();
})->with([
    'missing app' => ['AppOwning', []],
    'malformed app' => ['AppOwning', ['app_id' => 'not-a-number']],
    'missing instance node' => ['InstanceOwning', []],
    'malformed instance node' => ['InstanceOwning', ['node_id' => 'not-a-number']],
    'missing workspace instance' => ['WorkspaceOwning', []],
    'malformed workspace instance' => ['WorkspaceOwning', ['instance_id' => 0]],
    'missing process target' => ['ProcessOwning', []],
    'malformed process target type' => ['ProcessOwning', ['target_type' => 'node', 'target_id' => 1]],
]);

it('throws for syntactically valid missing raw identifiers', function (string $scopeName, array $input): void {
    /** @var ServingNode $scope */
    $scope = constant(ServingNode::class.'::'.$scopeName);

    resolver()->resolve(resolver_request(input: $input), $scope);
})->with([
    'app' => ['AppOwning', ['app_id' => 999_999]],
    'instance node' => ['InstanceOwning', ['node_id' => 999_999]],
    'workspace instance' => ['WorkspaceOwning', ['instance_id' => 999_999]],
    'process instance' => ['ProcessOwning', ['target_type' => 'instance', 'target_id' => 999_999]],
    'process workspace' => ['ProcessOwning', ['target_type' => 'workspace', 'target_id' => 999_999]],
])->throws(ModelNotFoundException::class);

function resolver(): ServingNodeResolver
{
    return app(ServingNodeResolver::class);
}

/** @param list<Node> $nodes @return list<int> */
function resolver_node_ids(array $nodes): array
{
    return array_map(static fn (Node $node): int => $node->id, $nodes);
}

/** @param array<string, mixed> $parameters @param array<string, mixed> $input */
function resolver_request(array $parameters = [], array $input = []): Request
{
    $route = new Route('GET', '/', static fn (): null => null);
    $request = Request::create('/', 'GET', $input);
    $route->bind($request);

    foreach ($parameters as $name => $value) {
        $route->setParameter($name, $value);
    }

    $request->setRouteResolver(static fn (): Route => $route);

    return $request;
}

function resolver_node(string $name, LifecycleStatus $status = LifecycleStatus::Active): Node
{
    return Node::query()->create([
        'name' => $name,
        'status' => $status,
        'public_ssh_host' => $name.'.example.test',
    ]);
}

function resolver_app(string $slug): OrbitApp
{
    return OrbitApp::query()->create([
        'name' => $slug,
        'slug' => $slug,
        'repository_url' => 'https://example.test/'.$slug.'.git',
    ]);
}

function resolver_instance(OrbitApp $app, Node $node, string $name): Instance
{
    return Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => $name,
        'environment' => 'testing',
        'checkout_path' => '/srv/'.$name,
        'hostname' => $name.'.example.test',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);
}

function resolver_workspace(Instance $instance, string $name): Workspace
{
    return Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => $name,
        'branch' => 'main',
        'checkout_path' => '/srv/'.$name,
        'hostname' => $name.'.example.test',
        'status' => LifecycleStatus::Active,
    ]);
}

function resolver_process(Instance|Workspace $owner): Process
{
    return $owner
        ->processes()
        ->create([
            'name' => 'worker',
            'runtime' => ProcessRuntime::Systemd,
            'working_directory' => '/srv/app',
            'runtime_config' => ['command' => 'php artisan queue:work'],
            'desired_state' => DesiredProcessState::Running,
            'status' => LifecycleStatus::Active,
        ]);
}
