<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Illuminate\Support\Str;

beforeEach(function (): void {
    $this->operator = Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->operator = $this->markAsGateway($this->operator);
    $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
});

describe('app creation', function (): void {
    it('creates an app with a default name and treats its slug and repository as immutable identity', function (): void {
        $requestId = (string) Str::uuid();
        $first = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/apps', [
                'slug' => 'acme',
                'repository_url' => 'git@github.com:acme/site.git',
            ]);

        $first
            ->assertCreated()
            ->assertJsonPath('data.name', 'acme')
            ->assertJsonPath('data.slug', 'acme')
            ->assertJsonPath('data.repository_url', 'git@github.com:acme/site.git')
            ->assertJsonStructure(['meta' => ['request_id']]);

        $second = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->postJson('/api/v1/apps', [
                'name' => 'Acme website',
                'slug' => 'acme',
                'repository_url' => 'git@github.com:acme/site.git',
                'defaults' => ['php_version' => '8.5'],
            ]);

        $second
            ->assertOk()
            ->assertJsonPath('data.id', $first->json('data.id'))
            ->assertJsonPath('data.name', 'Acme website')
            ->assertJsonPath('data.defaults.php_version', '8.5');

        expect(OrbitApp::query()->count())
            ->toBe(1)
            ->and(Activity::query()->where('request_id', $requestId)->sole()->command)
            ->toBe('app:new');

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->subject_type)
            ->toBe(OrbitApp::class)
            ->and($activity->subject_id)
            ->toBe($first->json('data.id'));
    });

    it('rejects an incompatible repository change on an existing app', function (): void {
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'git@github.com:acme/site.git',
        ]);

        $this
            ->postJson('/api/v1/apps', [
                'slug' => 'acme',
                'repository_url' => 'https://github.com/acme/other.git',
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'app.repository_change_unsupported');

        expect($app->refresh()->repository_url)->toBe('git@github.com:acme/site.git');
    });
});

describe('app defaults projection', function (): void {
    it('redacts create responses for an active Gateway peer without changing stored defaults', function (): void {
        $secrets = app_api_default_secrets();
        $defaults = app_api_sensitive_defaults($secrets);
        $publicDefaults = app_api_public_defaults();

        $response = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->postJson('/api/v1/apps', [
                'name' => 'Acme',
                'slug' => 'acme',
                'repository_url' => 'https://github.com/acme/site.git',
                'defaults' => $defaults,
            ])
            ->assertCreated()
            ->assertJsonPath('data.defaults', $publicDefaults);
        $app = OrbitApp::query()->where('slug', 'acme')->sole();

        app_api_expect_defaults_secrets_absent($response->getContent(), $secrets);
        app_api_expect_defaults_secrets_absent(print_r($response->json('data'), return: true), $secrets);
        app_api_expect_defaults_secrets_absent(print_r($app->toArray(), return: true), $secrets);
        expect(array_key_exists('defaults', $app->toArray()))
            ->toBeFalse()
            ->and($app->defaults)
            ->toBe($defaults);
    });

    it('redacts list and show responses for an active Gateway peer without changing stored defaults', function (): void {
        $secrets = app_api_default_secrets();
        $defaults = app_api_sensitive_defaults($secrets);
        $publicDefaults = app_api_public_defaults();
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
            'defaults' => $defaults,
        ]);

        $listed = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->getJson('/api/v1/apps')
            ->assertOk()
            ->assertJsonPath('data.0.defaults', $publicDefaults);
        $shown = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->getJson("/api/v1/apps/{$app->id}")
            ->assertOk()
            ->assertJsonPath('data.defaults', $publicDefaults);

        app_api_expect_defaults_secrets_absent($listed->getContent(), $secrets);
        app_api_expect_defaults_secrets_absent($shown->getContent(), $secrets);
        app_api_expect_defaults_secrets_absent(
            print_r([$listed->json('data.0'), $shown->json('data')], return: true),
            $secrets,
        );
        expect($app->refresh()->defaults)->toBe($defaults);
    });
});

describe('app defaults diagnostics', function (): void {
    it('redacts submitted defaults before activity persistence and serialization', function (): void {
        $requestId = (string) Str::uuid();
        $secrets = app_api_default_secrets();
        $defaults = app_api_sensitive_defaults($secrets);
        $publicDefaults = app_api_public_defaults();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/apps', [
                'slug' => 'acme',
                'repository_url' => 'https://github.com/acme/site.git',
                'defaults' => $defaults,
            ])
            ->assertCreated();
        $activity = Activity::query()->where('request_id', $requestId)->sole();
        $activityResponse = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->getJson("/api/v1/activities/{$activity->id}")
            ->assertOk()
            ->assertJsonPath('data.properties.input.defaults', $publicDefaults);

        app_api_expect_defaults_secrets_absent($activityResponse->getContent(), $secrets);
        app_api_expect_defaults_secrets_absent(
            print_r($activity->properties?->toArray(), return: true),
            $secrets,
        );
    });

    it('keeps submitted default secrets out of repository conflict errors and diagnostics', function (): void {
        $requestId = (string) Str::uuid();
        $errorSecret = (string) Str::uuid();
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
            'defaults' => ['php_version' => '8.5'],
        ]);

        $response = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/apps', [
                'slug' => 'acme',
                'repository_url' => 'https://github.com/acme/other.git',
                'defaults' => [
                    'nested' => ['api_token' => $errorSecret],
                    'diagnostic' => "request token={$errorSecret} branch=main",
                ],
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'app.repository_change_unsupported');
        $activity = Activity::query()->where('request_id', $requestId)->sole();
        $properties = $activity->properties?->toArray() ?? [];
        $activityResponse = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->getJson("/api/v1/activities/{$activity->id}")
            ->assertOk()
            ->assertJsonPath('data.properties.input.defaults.nested.api_token', '[REDACTED]')
            ->assertJsonPath(
                'data.properties.input.defaults.diagnostic',
                'request token=[REDACTED] branch=main',
            );
        $debugOutput = print_r($properties, return: true);

        expect($response->getContent())
            ->not->toContain($errorSecret)->and($activityResponse->getContent())
            ->not->toContain($errorSecret)->and($debugOutput)
            ->not->toContain($errorSecret)->and($app->refresh()->defaults)->toBe(['php_version' => '8.5']);
    });
});

describe('app lifecycle', function (): void {
    it('lists, shows, and removes apps by numeric id', function (): void {
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
        ]);

        $this
            ->getJson('/api/v1/apps')
            ->assertOk()
            ->assertJsonPath('data.0.id', $app->id);

        $this
            ->getJson("/api/v1/apps/{$app->id}")
            ->assertOk()
            ->assertJsonPath('data.slug', 'acme');

        $this
            ->deleteJson("/api/v1/apps/{$app->id}")
            ->assertOk()
            ->assertJsonPath('data.id', $app->id);

        expect(OrbitApp::query()->count())->toBe(0);
    });

    it('does not remove an app that still has instances', function (): void {
        $node = Node::query()->create([
            'name' => 'dev',
            'public_ssh_host' => '192.0.2.10',
        ]);
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
        ]);
        Instance::query()->create([
            'app_id' => $app->id,
            'node_id' => $node->id,
            'name' => 'dev',
            'environment' => 'development',
            'checkout_path' => '/home/orbit/apps/acme/dev',
            'hostname' => 'dev.dev.orbit',
            'certificate_mode' => 'orbit-ca',
        ]);

        $this
            ->deleteJson("/api/v1/apps/{$app->id}")
            ->assertConflict()
            ->assertJsonPath('error.code', 'app.has_instances');

        expect($app->fresh())->not->toBeNull();
    });
});

describe('app validation', function (): void {
    it('validates repository and slug input', function (array $payload, string $field): void {
        $this
            ->postJson('/api/v1/apps', $payload)
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed')
            ->assertJsonPath("error.details.{$field}.0", fn (string $message): bool => $message !== '');
    })->with([
        'invalid slug' => [
            [
                'slug' => '../acme',
                'repository_url' => 'https://github.com/acme/site.git',
            ],
            'slug',
        ],
        'repository contains whitespace' => [
            [
                'slug' => 'acme',
                'repository_url' => "https://github.com/acme/site.git\n--upload-pack=bad",
            ],
            'repository_url',
        ],
        'repository contains URL credentials' => [
            [
                'slug' => 'acme',
                'repository_url' => 'https://alice:super-secret@example.com/acme/site.git',
            ],
            'repository_url',
        ],
    ]);
});

describe('app list access', function (): void {
    it('shows all rows to fleet authority, accessible apps to a direct consumer, and denies a no-edge consumer', function (): void {
        $gateway = $this->operator;
        $accessibleNode = Node::query()->create([
            'name' => 'accessible-node',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.20',
            'wireguard_address' => '10.44.0.20',
        ]);
        $inaccessibleNode = Node::query()->create([
            'name' => 'inaccessible-node',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.21',
            'wireguard_address' => '10.44.0.21',
        ]);
        $directConsumer = Node::query()->create([
            'name' => 'direct-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.22',
            'wireguard_address' => '10.44.0.22',
        ]);
        $gatewayAccessConsumer = Node::query()->create([
            'name' => 'gateway-access-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.23',
            'wireguard_address' => '10.44.0.23',
        ]);
        $noEdgeConsumer = Node::query()->create([
            'name' => 'no-edge-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.24',
            'wireguard_address' => '10.44.0.24',
        ]);
        $directConsumer->accessibleNodes()->attach($accessibleNode);
        $gatewayAccessConsumer->accessibleNodes()->attach($gateway);
        $unplaced = OrbitApp::query()->create([
            'name' => 'Unplaced',
            'slug' => 'unplaced',
            'repository_url' => 'https://example.test/unplaced.git',
        ]);
        $accessible = OrbitApp::query()->create([
            'name' => 'Accessible',
            'slug' => 'accessible',
            'repository_url' => 'https://example.test/accessible.git',
        ]);
        $inaccessible = OrbitApp::query()->create([
            'name' => 'Inaccessible',
            'slug' => 'inaccessible',
            'repository_url' => 'https://example.test/inaccessible.git',
        ]);
        Instance::query()->create([
            'app_id' => $accessible->id,
            'node_id' => $accessibleNode->id,
            'name' => 'main',
            'environment' => 'development',
            'checkout_path' => '/srv/accessible',
            'hostname' => 'accessible.example.test',
            'certificate_mode' => 'orbit-ca',
        ]);
        Instance::query()->create([
            'app_id' => $inaccessible->id,
            'node_id' => $inaccessibleNode->id,
            'name' => 'main',
            'environment' => 'development',
            'checkout_path' => '/srv/inaccessible',
            'hostname' => 'inaccessible.example.test',
            'certificate_mode' => 'orbit-ca',
        ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
            ->getJson('/api/v1/apps')
            ->assertOk()
            ->assertJsonPath('data.*.id', [$inaccessible->id, $accessible->id, $unplaced->id]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gatewayAccessConsumer->wireguard_address])
            ->getJson('/api/v1/apps')
            ->assertOk()
            ->assertJsonPath('data.*.id', [$inaccessible->id, $accessible->id, $unplaced->id]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $directConsumer->wireguard_address])
            ->getJson('/api/v1/apps')
            ->assertOk()
            ->assertJsonPath('data.*.id', [$accessible->id]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $noEdgeConsumer->wireguard_address])
            ->getJson('/api/v1/apps')
            ->assertForbidden()
            ->assertJsonPath('error.code', 'node_access.required');
    });
});

/** @return array{database: string, query: string, command: string, environment: string} */
function app_api_default_secrets(): array
{
    return [
        'database' => (string) Str::uuid(),
        'query' => (string) Str::uuid(),
        'command' => (string) Str::uuid(),
        'environment' => (string) Str::uuid(),
    ];
}

/**
 * @param array{database: string, query: string, command: string, environment: string} $secrets
 *
 * @return array<string, mixed>
 */
function app_api_sensitive_defaults(array $secrets): array
{
    return [
        'php_version' => '8.5',
        'config' => [
            'app_name' => 'Acme',
            'database' => [
                'host' => 'database.internal',
                'password' => $secrets['database'],
            ],
            'webhook' => "https://example.test/deploy?access_token={$secrets['query']}&branch=main",
            'command' => "deploy --api-key={$secrets['command']} --branch=main",
        ],
        'environment' => [
            'APP_ENV' => 'production',
            'DATABASE_URL' => "postgres://orbit:{$secrets['environment']}@database.internal/acme",
        ],
    ];
}

/** @return array<string, mixed> */
function app_api_public_defaults(): array
{
    $redacted = '[REDACTED]';

    return [
        'php_version' => '8.5',
        'config' => [
            'app_name' => 'Acme',
            'database' => [
                'host' => 'database.internal',
                'password' => $redacted,
            ],
            'webhook' => 'https://example.test/deploy?access_token=[REDACTED]&branch=main',
            'command' => 'deploy --api-key=[REDACTED] --branch=main',
        ],
        'environment' => [
            'APP_ENV' => $redacted,
            'DATABASE_URL' => $redacted,
        ],
    ];
}

/** @param array<string, string> $secrets */
function app_api_expect_defaults_secrets_absent(string $output, array $secrets): void
{
    expect($output)->not->toContain(...array_values($secrets));
}
