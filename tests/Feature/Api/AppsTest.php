<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Illuminate\Support\Str;

describe('app API', function (): void {
    beforeEach(function (): void {
        Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.2',
        ]);
        $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
    });

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
