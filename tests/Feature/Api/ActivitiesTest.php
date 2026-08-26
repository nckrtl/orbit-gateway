<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

beforeEach(function (): void {
    $this->operator = Node::query()->create([
        'name' => 'activity-operator',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
});

describe('activity recording', function (): void {
    it('records read commands with the public CLI command name', function (): void {
        $this->getJson('/api/v1/nodes')->assertOk();

        expect(Activity::query()->sole()->command)->toBe('node:list');
    });
});

describe('activity reads', function (): void {
    it('lists the latest completed activity without returning its own running attempt', function (): void {
        activity_api_record(
            requestId: '11111111-1111-4111-8111-111111111111',
            command: 'app:list',
            status: 'succeeded',
            properties: ['method' => 'GET', 'path' => 'api/v1/apps'],
        );
        $latest = activity_api_record(
            requestId: '22222222-2222-4222-8222-222222222222',
            command: 'instance:new',
            status: 'failed',
            properties: ['method' => 'POST', 'path' => 'api/v1/instances', 'output_truncated' => false],
            errorCode: 'instance.provision_failed',
        );
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/activities?limit=1')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $latest->id)
            ->assertJsonPath('data.0.request_id', '22222222-2222-4222-8222-222222222222')
            ->assertJsonPath('data.0.command', 'instance:new')
            ->assertJsonPath('data.0.status', 'failed')
            ->assertJsonPath('data.0.error_code', 'instance.provision_failed')
            ->assertJsonPath('data.0.properties.output_truncated', false)
            ->assertJsonPath('meta.limit', 1)
            ->assertJsonPath('meta.count', 1)
            ->assertJsonPath('meta.request_id', $requestId);

        $attempt = Activity::query()->where('request_id', $requestId)->sole();

        expect($attempt->command)
            ->toBe('activity:list')
            ->and($attempt->status)
            ->toBe('succeeded');
    });

    it('shows one activity with its bounded diagnostic context', function (): void {
        $activity = activity_api_record(
            requestId: '33333333-3333-4333-8333-333333333333',
            command: 'process:start',
            status: 'failed',
            properties: [
                'method' => 'POST',
                'path' => 'api/v1/processes/7/start',
                'stdout' => 'bounded output',
                'output_truncated' => true,
            ],
            errorCode: 'process.start_failed',
        );

        $this
            ->getJson("/api/v1/activities/{$activity->id}")
            ->assertOk()
            ->assertJsonPath('data.id', $activity->id)
            ->assertJsonPath('data.request_id', '33333333-3333-4333-8333-333333333333')
            ->assertJsonPath('data.command', 'process:start')
            ->assertJsonPath('data.properties.stdout', 'bounded output')
            ->assertJsonPath('data.properties.output_truncated', true);
    });

    it('finds the exact command attempt by request ID', function (): void {
        $expected = activity_api_record(
            requestId: '44444444-4444-4444-8444-444444444444',
            command: 'node:provision',
            status: 'failed',
            properties: ['method' => 'POST', 'path' => 'api/v1/nodes'],
            errorCode: 'node.ssh_host_fingerprint_required',
        );
        activity_api_record(
            requestId: '55555555-5555-4555-8555-555555555555',
            command: 'app:list',
            status: 'succeeded',
            properties: ['method' => 'GET', 'path' => 'api/v1/apps'],
        );

        $this
            ->getJson('/api/v1/activities?request_id=44444444-4444-4444-8444-444444444444')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $expected->id)
            ->assertJsonPath('data.0.command', 'node:provision');
    });

    it('validates the list bound and returns the standard missing-resource envelope', function (): void {
        $this
            ->getJson('/api/v1/activities?limit=0')
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $this
            ->getJson('/api/v1/activities/999')
            ->assertNotFound()
            ->assertJsonPath('error.code', 'http.404');
    });
});

describe('activity access and redaction', function (): void {
    it('rejects callers outside the active WireGuard peer set', function (): void {
        activity_api_record(
            requestId: '66666666-6666-4666-8666-666666666666',
            command: 'process:logs',
            status: 'succeeded',
            properties: ['stdout' => 'private output'],
        );

        $this
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
            ->getJson('/api/v1/activities')
            ->assertForbidden()
            ->assertJsonPath('error.code', 'peer.identity_unknown')
            ->assertJsonMissing(['private output']);
    });

    it('re-sanitizes stored diagnostics and emits stable public subject vocabulary', function (): void {
        $credential = 'sentinel-serialized-activity-credential';
        $invalidKeyCredential = 'sentinel-serialized-invalid-key';
        $activity = activity_api_record(
            requestId: '77777777-7777-4777-8777-777777777777',
            command: 'process:add',
            status: 'failed',
            properties: ['safe' => ['status' => 'failed']],
        );
        $activity->update([
            'subject_type' => Node::class,
            'subject_id' => $this->operator->id,
        ]);
        $unsafeProperties = json_encode(
            activity_api_sensitive_properties($credential, $invalidKeyCredential),
            JSON_THROW_ON_ERROR,
        );
        DB::table('activity_log')->where('id', $activity->id)->update(['properties' => $unsafeProperties]);

        expect(DB::table('activity_log')->where('id', $activity->id)->value('properties'))
            ->toContain($credential, $invalidKeyCredential);

        $response = $this
            ->getJson("/api/v1/activities/{$activity->id}")
            ->assertOk()
            ->assertJsonPath('data.subject_type', 'node')
            ->assertJsonPath('data.properties', activity_api_sanitized_properties());

        expect($response->getContent())->not->toContain($credential, $invalidKeyCredential);
    });

    it('recursively sanitizes arbitrary properties before persistence and API serialization', function (): void {
        $credential = 'sentinel-activity-credential';
        $invalidKeyCredential = 'sentinel-invalid-property-key';
        $activity = activity_api_record(
            requestId: '88888888-8888-4888-8888-888888888888',
            command: 'process:add',
            status: 'failed',
            properties: activity_api_sensitive_properties($credential, $invalidKeyCredential),
            errorCode: 'process.create_failed',
        );
        $rawProperties = DB::table('activity_log')
            ->where('id', $activity->id)
            ->value('properties');
        $persistedProperties = $activity->refresh()->properties?->toArray() ?? [];
        $debugOutput = print_r($persistedProperties, return: true);

        expect($rawProperties)
            ->toBeString()
            ->not
            ->toContain($credential, $invalidKeyCredential)
            ->toContain('main');
        expect($persistedProperties)->toBe(activity_api_sanitized_properties());
        expect($debugOutput)->not->toContain($credential, $invalidKeyCredential);

        $response = $this
            ->getJson("/api/v1/activities/{$activity->id}")
            ->assertOk()
            ->assertJsonPath('data.properties', activity_api_sanitized_properties());

        expect($response->getContent())->not->toContain($credential, $invalidKeyCredential);
    });
});

/** @return array<string, mixed> */
function activity_api_sensitive_properties(string $credential, string $invalidKeyCredential): array
{
    return [
        'safe' => [
            'status' => 'failed',
            'branch' => 'main',
        ],
        'defaults' => [
            'database' => ['password' => $credential],
            'repository' => "https://example.test/repo.git?token={$credential}&branch=main",
        ],
        'query' => [
            'api_key' => $credential,
            'access_token' => $credential,
            'branch' => 'main',
        ],
        'command' => "git clone https://example.test/repo.git?refresh_token={$credential}&branch=main --token={$credential}",
        'environment' => [
            'APP_ENV' => $credential,
            "INVALID\n{$invalidKeyCredential}" => $credential,
        ],
        "unsafe\n{$invalidKeyCredential}" => $credential,
    ];
}

/** @return array<string, mixed> */
function activity_api_sanitized_properties(): array
{
    $redacted = '[REDACTED]';

    return [
        'safe' => [
            'status' => 'failed',
            'branch' => 'main',
        ],
        'defaults' => [
            'database' => ['password' => $redacted],
            'repository' => 'https://example.test/repo.git?token=[REDACTED]&branch=main',
        ],
        'query' => [
            'api_key' => $redacted,
            'access_token' => $redacted,
            'branch' => 'main',
        ],
        'command' => 'git clone https://example.test/repo.git?refresh_token=[REDACTED]&branch=main --token=[REDACTED]',
        'environment' => [
            'APP_ENV' => $redacted,
            '[INVALID_ENVIRONMENT_NAME]' => $redacted,
        ],
        '[INVALID_PROPERTY_NAME]' => $redacted,
    ];
}

/** @param array<string, mixed> $properties */
function activity_api_record(
    string $requestId,
    string $command,
    string $status,
    array $properties,
    ?string $errorCode = null,
): Activity {
    return Activity::query()->create([
        'log_name' => 'commands',
        'description' => $command,
        'event' => 'command',
        'properties' => $properties,
        'request_id' => $requestId,
        'command' => $command,
        'caller_ip' => '10.44.0.2',
        'status' => $status,
        'duration_ms' => 12,
        'exit_code' => $status === 'failed' ? 1 : 0,
        'error_code' => $errorCode,
    ]);
}
