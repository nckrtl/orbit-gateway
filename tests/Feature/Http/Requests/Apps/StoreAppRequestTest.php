<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Node;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

beforeEach(function (): void {
    Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
});

it('accepts supported repository origins', function (string $repositoryUrl): void {
    $this
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => $repositoryUrl,
        ])
        ->assertCreated()
        ->assertJsonPath('data.repository_url', $repositoryUrl);

    expect(OrbitApp::query()->sole()->repository_url)->toBe($repositoryUrl);
})->with([
    'HTTPS URL' => ['https://github.com/acme/site.git'],
    'SSH URL' => ['ssh://git@github.com/acme/site.git'],
    'scp-like SSH origin' => ['git@github.com:acme/site.git'],
]);

it('returns 422 without persistence or secret exposure for credential-bearing repository queries', function (string $queryKey): void {
    Config::set('app.debug', true);
    $requestId = (string) Str::uuid();
    $sentinel = "sentinel-{$queryKey}-value";
    $repositoryUrl =
        'https://example.test/acme/site.git?'.rawurlencode($queryKey).'='.rawurlencode($sentinel).'&branch=main';

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => $repositoryUrl,
        ]);

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed')
        ->assertJsonPath(
            'error.details.repository_url.0',
            'The repository URL must be a valid HTTPS or SSH Git origin.',
        );

    $activity = Activity::query()->where('request_id', $requestId)->sole();
    $storedActivity = json_encode($activity->getAttributes(), JSON_THROW_ON_ERROR);
    $serializedActivity = $this
        ->getJson("/api/v1/activities/{$activity->id}")
        ->assertOk()
        ->getContent();

    expect(OrbitApp::query()->exists())
        ->toBeFalse()
        ->and($activity->status)
        ->toBe('failed')
        ->and($activity->error_code)
        ->toBe('validation.failed');
    expect($response->getContent())->not->toContain($sentinel, $repositoryUrl);
    expect($storedActivity)->not->toContain($sentinel, $repositoryUrl);
    expect($serializedActivity)
        ->not->toContain($sentinel, $repositoryUrl);
})->with([
    'token' => ['token'],
    'API key' => ['api_key'],
    'hyphenated API key' => ['api-key'],
    'camel-case API key' => ['ApiKey'],
    'API token' => ['api_token'],
    'camel-case API token' => ['apiToken'],
    'access token' => ['access_token'],
    'hyphenated access token' => ['access-token'],
    'camel-case access token' => ['accessToken'],
    'refresh token' => ['refresh_token'],
    'hyphenated refresh token' => ['refresh-token'],
    'camel-case refresh token' => ['refreshToken'],
    'password' => ['password'],
    'secret' => ['secret'],
    'bearer' => ['bearer'],
]);

it('returns 422 without persistence or secret exposure for embedded repository credentials', function (
    string $repositoryUrl,
): void {
    Config::set('app.debug', true);
    $requestId = (string) Str::uuid();
    $sentinel = 'sentinel-repository-password';
    $repositoryUrl = str_replace('SENTINEL', $sentinel, $repositoryUrl);

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => $repositoryUrl,
        ]);

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed')
        ->assertJsonPath(
            'error.details.repository_url.0',
            'The repository URL must be a valid HTTPS or SSH Git origin.',
        );

    $activity = Activity::query()->where('request_id', $requestId)->sole();
    $storedActivity = json_encode($activity->getAttributes(), JSON_THROW_ON_ERROR);
    $serializedActivity = $this
        ->getJson("/api/v1/activities/{$activity->id}")
        ->assertOk()
        ->getContent();
    $debugOutput = print_r([
        'response' => $response->json(),
        'activity' => $activity->toArray(),
    ], return: true);

    expect(OrbitApp::query()->exists())
        ->toBeFalse()
        ->and($activity->status)
        ->toBe('failed')
        ->and($activity->error_code)
        ->toBe('validation.failed');
    expect($response->getContent())
        ->not->toContain($sentinel, $repositoryUrl)->and($storedActivity)
        ->not->toContain($sentinel, $repositoryUrl)->and($serializedActivity)
        ->not->toContain($sentinel, $repositoryUrl)->and($debugOutput)
        ->not->toContain($sentinel, $repositoryUrl);
})->with([
    'HTTPS userinfo' => ['https://SENTINEL@example.test/acme/site.git'],
    'HTTPS password' => ['https://git:SENTINEL@example.test/acme/site.git'],
    'SSH password' => ['ssh://git:SENTINEL@example.test/acme/site.git'],
]);

it('returns 422 without persistence when a repository origin contains a query or fragment', function (string $repositoryUrl): void {
    $this
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => $repositoryUrl,
        ])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed')
        ->assertJsonPath(
            'error.details.repository_url.0',
            'The repository URL must be a valid HTTPS or SSH Git origin.',
        );

    expect(OrbitApp::query()->exists())->toBeFalse();
})->with([
    'HTTPS query' => ['https://example.test/acme/site.git?branch=main'],
    'scp-like SSH query' => ['git@example.test:acme/site.git?branch=main'],
    'HTTPS fragment' => ['https://example.test/acme/site.git#main'],
    'scp-like SSH fragment' => ['git@example.test:acme/site.git#main'],
]);
