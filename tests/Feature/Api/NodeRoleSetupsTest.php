<?php

declare(strict_types=1);

use App\Domain\MacOs\MacOsAppDevSetupRenderer;
use App\Domain\MacOs\MacOsAppDevVerifier;
use App\Domain\MacOs\MacOsProtectedCheck;
use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\MacOs\MacOsAppDevSetupScriptRenderer;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\Support\NodeRoleSetupFakeRenderer;
use Tests\Support\NodeRoleSetupFakeVerifier;

/** @mago-expect lint:halstead The route contract scenarios stay together for shared caller and activity setup. */
describe('macOS app-dev setup routes', function (): void {
    beforeEach(function (): void {
        $this->renderer = new NodeRoleSetupFakeRenderer;
        app()->instance(MacOsAppDevSetupRenderer::class, $this->renderer);
        $this->verifier = new NodeRoleSetupFakeVerifier;
        app()->instance(MacOsAppDevVerifier::class, $this->verifier);
    });

    it('registers the native setup renderer and verifier behind the Task 1 contracts', function (): void {
        app()->forgetInstance(MacOsAppDevSetupRenderer::class);
        app()->forgetInstance(MacOsAppDevVerifier::class);

        expect(app()->bound(MacOsAppDevSetupRenderer::class))
            ->toBeTrue()
            ->and(app()->bound(MacOsAppDevVerifier::class))
            ->toBeTrue();
    });

    it('runs the concrete setup renderer through the caller-derived route', function (): void {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'public_ssh_host' => '192.0.2.1',
            'ssh_user' => 'orbit',
            'wireguard_address' => '10.44.0.1',
        ]);
        $gateway
            ->roles()
            ->create([
                'role' => RoleName::Gateway,
                'status' => LifecycleStatus::Active,
            ]);
        $node = setup_node_record();
        app()->instance(SshKeyProvider::class, new class implements SshKeyProvider {
            public function privateKeyPath(): string
            {
                return '/gateway/id_ed25519';
            }

            public function publicKey(): string
            {
                return 'ssh-ed25519 AAAAC3NzaGatewayKey orbit-gateway';
            }
        });
        app()->forgetInstance(MacOsAppDevSetupRenderer::class);

        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/script', setup_script_facts())
            ->assertOk()
            ->assertJsonPath('data.role', 'app-dev');

        expect(app(MacOsAppDevSetupRenderer::class))
            ->toBeInstanceOf(MacOsAppDevSetupScriptRenderer::class)
            ->and($response->json('data.summary'))
            ->toContain('Enable Remote Login')
            ->and($response->json('data.script'))
            ->toStartWith("#!/bin/bash\n")
            ->toContain(
                "WIREGUARD_ADDRESS='10.44.0.8'",
                "GATEWAY_WIREGUARD_ADDRESS='10.44.0.1'",
                'no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc',
            )
            ->and($node->refresh()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($gateway->refresh()->status)
            ->toBe(LifecycleStatus::Active);
    });

    it('derives the provisioning Darwin caller and returns a bounded setup script', function (): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();

        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/script', [
                'platform' => 'darwin',
                'architecture' => 'arm64',
                'username' => 'nckrtl',
                'home_directory' => '/Users/nckrtl',
            ])
            ->assertOk()
            ->assertJsonPath('data.role', 'app-dev')
            ->assertJsonPath('data.summary', 'Install the approved local app-dev dependencies.')
            ->assertJsonPath('data.script', "#!/bin/bash\nexit 0\n")
            ->assertJsonPath('meta.request_id', $requestId);

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->properties?->get('input'))
            ->toBe(['platform' => 'darwin', 'architecture' => 'arm64'])
            ->and($activity->caller_node_id)
            ->toBe($node->id)
            ->and(json_encode($activity->properties?->toArray()))
            ->not->toContain('nckrtl')
            ->not->toContain('/Users/nckrtl')
            ->not->toContain('#!/bin/bash')->and(Schema::hasTable(
                'node_role_setups',
            ))->toBeFalse()->and(Schema::hasTable('setup_operations'))->toBeFalse();
    });

    it('activates the caller and assignment after a zero result and live verification', function (): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => 'setup complete',
            ])
            ->assertOk()
            ->assertJsonPath('data.node_id', $node->id)
            ->assertJsonPath('data.assignment.role', 'app-dev')
            ->assertJsonPath('data.assignment.status', 'active')
            ->assertJsonPath('data.assignment.local_action_required', false)
            ->assertJsonPath('data.assignment.local_command', null)
            ->assertJsonPath('meta.request_id', $requestId);

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($this->verifier->calls)
            ->toBe(1);
    });

    it('accepts an empty bounded diagnostic transcript on successful setup', function (): void {
        $node = setup_node_record();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => '',
            ])
            ->assertOk()
            ->assertJsonPath('data.assignment.status', 'active');
    });

    it('requires a native JSON integer exit code', function (string $rawExitCode): void {
        $node = setup_node_record();

        $this
            ->call(
                method: 'POST',
                uri: '/api/v1/node-role-setups/app-dev/result',
                server: [
                    'CONTENT_TYPE' => 'application/json',
                    'REMOTE_ADDR' => $node->wireguard_address,
                ],
                content: '{"exit_code":'.$rawExitCode.',"diagnostics":""}',
            )
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        expect($this->verifier->calls)->toBe(0);
    })->with([
        'numeric string' => ['"0"'],
        'float' => ['0.0'],
    ]);

    it('does not persist invalid nested diagnostics or their bytes', function (): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();
        $suffix = 'RAW_INVALID_DIAGNOSTIC_SUFFIX';

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => [str_repeat(string: 'a', times: 32_768).$suffix],
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $properties = Activity::query()->where('request_id', $requestId)->sole()->properties?->toArray() ?? [];

        expect(data_get(target: $properties, key: 'input'))
            ->toBe(['exit_code' => 0])
            ->and(json_encode($properties))
            ->not->toContain($suffix);
    });

    it('rejects diagnostics by byte length without splitting multibyte activity data', function (): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();
        $diagnostics = 'é'.str_repeat(string: 'a', times: 32_767);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 1,
                'diagnostics' => $diagnostics,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $properties = Activity::query()->where('request_id', $requestId)->sole()->properties?->toArray() ?? [];
        $stored = data_get(target: $properties, key: 'input.diagnostics');

        expect($stored)
            ->toBeString()
            ->and(strlen($stored))
            ->toBeLessThanOrEqual(32_768)
            ->and(mb_check_encoding(value: $stored, encoding: 'UTF-8'))
            ->toBeTrue()
            ->and($this->verifier->calls)
            ->toBe(0);
    });

    it('records a nonzero local result as one stable setup failure without verification', function (): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();
        $credentialKey = str_rot13(string: 'cnffjbeq');
        $secret = "{$credentialKey}=RAW_DIAGNOSTIC_SENTINEL";

        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 12,
                'diagnostics' => "failed {$secret}\x00",
            ]);

        $response
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'macos.setup_failed')
            ->assertJsonPath('error.details.failed_step', 'local-setup');
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->failed_step)
            ->toBe('local-setup')
            ->and($node->error_code)
            ->toBe('macos.setup_failed')
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($this->verifier->calls)
            ->toBe(0)
            ->and($activity->caller_node_id)
            ->toBe($node->id)
            ->and(json_encode($activity->properties?->toArray()))
            ->not->toContain('RAW_DIAGNOSTIC_SENTINEL')
            ->not->toContain("\u0000")->and($response->getContent())
            ->not->toContain('RAW_DIAGNOSTIC_SENTINEL');
    });

    it('omits unsafe verifier details from the stable error contract', function (): void {
        $node = setup_node_record();
        $this->verifier->failure = new ResourceOperationException(
            errorCode: 'macos.verification_failed',
            message: 'The live identity verification failed.',
            status: 502,
            safeDetails: [
                'check' => 'RAW_SAFE_SENTINEL',
                'local_command' => 'RAW_SAFE_SENTINEL',
            ],
        );

        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => 'done',
            ]);

        $response
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'macos.verification_failed')
            ->assertJsonPath('error.details', []);

        expect($response->getContent())
            ->not
            ->toContain('RAW_SAFE_SENTINEL')
            ->and($node->refresh()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->error_code)
            ->toBe('macos.verification_failed');
    });

    it('preserves node and role lifecycle bytes when protected state needs a local action', function (): void {
        $node = setup_node_record();
        $node->update([
            'failed_step' => 'private-dns',
            'error_code' => 'node.dns_projection_failed',
        ]);
        $assignment = $node->roles()->sole();
        $assignment->update([
            'failed_step' => 'private-dns',
            'error_code' => 'node.dns_projection_failed',
        ]);
        $fields = ['status', 'failed_step', 'error_code'];
        $before = json_encode([
            'node' => $node->refresh()->only($fields),
            'role' => $assignment->refresh()->only($fields),
        ], JSON_THROW_ON_ERROR);
        $this->verifier->failure = new MacOsProtectedDriftException(MacOsProtectedCheck::RootCaTrust);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => 'done',
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'macos.local_action_required')
            ->assertJsonPath('error.details.check', 'root-ca-trust')
            ->assertJsonPath('error.details.local_command', 'orbit gateway:trust');

        $after = json_encode([
            'node' => $node->refresh()->only($fields),
            'role' => $assignment->refresh()->only($fields),
        ], JSON_THROW_ON_ERROR);

        expect($after)->toBe($before);
    });

    it('resets only a setup-owned failed state when a new script is requested', function (): void {
        $node = setup_node_record(LifecycleStatus::Failed, LifecycleStatus::Failed);
        $node->update(['failed_step' => 'local-setup', 'error_code' => 'macos.setup_failed']);
        $node->roles()->update(['failed_step' => 'local-setup', 'error_code' => 'macos.setup_failed']);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/script', setup_script_facts())
            ->assertOk();

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($node->failed_step)
            ->toBeNull()
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($this->renderer->calls)
            ->toBe(1);
    });

    it('rejects a result retry for a failure that setup does not own', function (): void {
        $node = setup_node_record(LifecycleStatus::Failed, LifecycleStatus::Failed);
        $node->update(['failed_step' => 'local-setup', 'error_code' => 'node.role_conflict']);
        $node->roles()->update(['failed_step' => 'local-setup', 'error_code' => 'node.role_conflict']);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/result', [
                'exit_code' => 0,
                'diagnostics' => 'done',
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'node.role_setup_not_ready');

        expect($this->verifier->calls)
            ->toBe(0)
            ->and($node->refresh()->error_code)
            ->toBe('node.role_conflict')
            ->and($node->roles()->sole()->error_code)
            ->toBe('node.role_conflict');
    });

    it('rejects enrollment-owned failure before rendering with allow-listed safe details', function (): void {
        $node = setup_node_record(LifecycleStatus::Failed, LifecycleStatus::Failed);
        $node->update([
            'failed_step' => 'private-dns',
            'error_code' => 'node.dns_projection_failed',
        ]);
        $node->roles()->update([
            'failed_step' => 'private-dns',
            'error_code' => 'node.dns_projection_failed',
        ]);
        $requestId = (string) Str::uuid();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/node-role-setups/app-dev/script', setup_script_facts())
            ->assertConflict()
            ->assertJsonPath('error.code', 'node.role_setup_not_ready')
            ->assertJsonPath('error.details.failed_step', 'private-dns')
            ->assertJsonPath('error.details.local_action_required', false)
            ->assertJsonPath('error.details.local_command', null);

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->caller_node_id)
            ->toBe($node->id)
            ->and($activity->error_code)
            ->toBe('node.role_setup_not_ready')
            ->and($this->renderer->calls)
            ->toBe(0);
    });

    it('rejects an active assignment on both setup routes', function (string $path, array $body): void {
        $node = setup_node_record(LifecycleStatus::Active, LifecycleStatus::Active);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson($path, $body)
            ->assertConflict()
            ->assertJsonPath('error.code', 'node.role_setup_not_required');
    })->with([
        'script' => ['/api/v1/node-role-setups/app-dev/script', setup_script_facts()],
        'result' => ['/api/v1/node-role-setups/app-dev/result', ['exit_code' => 0, 'diagnostics' => 'done']],
    ]);

    it('rejects setup facts that do not match the registered caller before rendering', function (array $facts): void {
        $node = setup_node_record();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/script', $facts)
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        expect($this->renderer->calls)->toBe(0);
    })->with([
        'architecture' => [[...setup_script_facts(), 'architecture' => 'x86_64']],
        'username' => [[...setup_script_facts(), 'username' => 'someone']],
        'home' => [[...setup_script_facts(), 'home_directory' => '/Users/someone']],
    ]);

    it('rejects unknown or duplicate setup keys before rendering and stores empty activity input', function (string $json): void {
        $node = setup_node_record();
        $requestId = (string) Str::uuid();

        $response = $this->call(
            method: 'POST',
            uri: '/api/v1/node-role-setups/app-dev/script',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'REMOTE_ADDR' => $node->wireguard_address,
                'HTTP_X_ORBIT_REQUEST_ID' => $requestId,
            ],
            content: $json,
        );

        $response
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->properties?->get('input'))
            ->toBeEmpty()
            ->and($this->renderer->calls)
            ->toBe(0)
            ->and($response->getContent())
            ->not->toContain('RAW_SETUP_SENTINEL')->and(json_encode($activity->properties?->toArray()))
            ->not->toContain('RAW_SETUP_SENTINEL');
    })->with([
        'unknown' => [
            '{"platform":"darwin","architecture":"arm64","username":"nckrtl","home_directory":"/Users/nckrtl","extra":"RAW_SETUP_SENTINEL"}',
        ],
        'duplicate' => [
            '{"platform":"darwin","architecture":"arm64","username":"RAW_SETUP_SENTINEL","user\\u006eame":"nckrtl","home_directory":"/Users/nckrtl"}',
        ],
    ]);

    it('rejects a registered Darwin caller without app-dev', function (): void {
        $node = Node::query()->create([
            'name' => 'roleless-mini',
            'status' => LifecycleStatus::Provisioning,
            'platform' => 'darwin',
            'architecture' => 'arm64',
            'public_ssh_host' => '10.44.0.9',
            'ssh_user' => 'nckrtl',
            'wireguard_address' => '10.44.0.9',
        ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->postJson('/api/v1/node-role-setups/app-dev/script', setup_script_facts())
            ->assertConflict()
            ->assertJsonPath('error.code', 'node.role_setup_not_assigned');
    });

    it('rejects unknown, non-Darwin, and spoofed setup callers', function (
        string $remoteAddress,
        ?string $registeredPlatform,
    ): void {
        if ($registeredPlatform !== null) {
            Node::query()->create([
                'name' => 'linux-node',
                'status' => LifecycleStatus::Provisioning,
                'platform' => $registeredPlatform,
                'architecture' => 'x86_64',
                'public_ssh_host' => '192.0.2.20',
                'wireguard_address' => $remoteAddress,
            ]);
        }

        $this
            ->withServerVariables(['REMOTE_ADDR' => $remoteAddress])
            ->withHeaders([
                'X-Orbit-Peer-Address' => '10.44.0.8',
                'X-Forwarded-For' => '10.44.0.8',
            ])
            ->postJson('/api/v1/node-role-setups/app-dev/script', setup_script_facts())
            ->assertForbidden()
            ->assertJsonPath('error.code', 'peer.identity_unknown');

        expect($this->renderer->calls)->toBe(0);
    })->with([
        'unknown' => ['10.44.0.99', null],
        'non-Darwin' => ['10.44.0.7', 'linux'],
        'loopback without trusted FastCGI variables' => ['127.0.0.1', null],
    ]);
});

/** @return array{platform: string, architecture: string, username: string, home_directory: string} */
function setup_script_facts(): array
{
    return [
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'username' => 'nckrtl',
        'home_directory' => '/Users/nckrtl',
    ];
}

function setup_node_record(
    LifecycleStatus $nodeStatus = LifecycleStatus::Provisioning,
    LifecycleStatus $roleStatus = LifecycleStatus::Provisioning,
): Node {
    $node = Node::query()->create([
        'name' => 'mini',
        'status' => $nodeStatus,
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'tld' => 'test',
        'public_ssh_host' => '10.44.0.8',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.8',
        'wireguard_public_key' => base64_encode(str_repeat(string: "\x01", times: 32)),
    ]);
    $node->roles()->create([
        'role' => RoleName::AppDev,
        'status' => $roleStatus,
    ]);

    return $node;
}
