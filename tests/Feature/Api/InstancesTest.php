<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Illuminate\Support\Str;

/** @mago-expect lint:halstead The shared fixture keeps all instance API state transitions consistent. */
describe('instance API', function (): void {
    beforeEach(function (): void {
        $this->runtime = new class implements AppDevRuntimeConverger {
            /** @var list<string> */
            public array $calls = [];

            public bool $fail = false;

            public function convergeInstance(Instance $instance): void
            {
                $this->calls[] = "instance:{$instance->id}:{$instance->php_version}";

                if ($this->fail) {
                    throw new RuntimeConvergenceException(
                        step: 'php-fpm',
                        errorCode: 'instance.php_fpm_failed',
                        message: 'PHP-FPM failed.',
                    );
                }
            }

            public function removeInstance(Instance $instance): void
            {
                $this->calls[] = "instance-remove:{$instance->id}";

                if ($this->fail) {
                    throw new RuntimeConvergenceException(
                        step: 'instance-source-remove',
                        errorCode: 'instance.remove_failed',
                        message: 'Instance removal failed.',
                    );
                }
            }

            public function convergeWorkspace(\App\Models\Workspace $workspace): void {}

            public function removeWorkspace(\App\Models\Workspace $workspace): void {}
        };
        app()->instance(AppDevRuntimeConverger::class, $this->runtime);

        $this->node = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.10',
            'ssh_user' => 'orbit',
            'wireguard_address' => '10.44.0.3',
        ]);
        $this->node
            ->roles()
            ->create([
                'role' => RoleName::AppDev,
                'status' => LifecycleStatus::Active,
            ]);
        $this->orbitApp = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'git@github.com:acme/site.git',
        ]);
    });

    it('creates an app-dev instance with derived defaults and converges retries', function (): void {
        $requestId = (string) Str::uuid();
        $first = $this->withHeader('X-Orbit-Request-Id', $requestId)->postJson('/api/v1/instances', [
            'app_id' => $this->orbitApp->id,
            'node_id' => $this->node->id,
            'name' => 'dev',
        ]);

        $first
            ->assertCreated()
            ->assertJsonPath('data.environment', 'development')
            ->assertJsonPath('data.checkout_path', '/home/orbit/apps/acme')
            ->assertJsonPath('data.document_root', 'public')
            ->assertJsonPath('data.php_version', '8.5')
            ->assertJsonPath('data.hostname', 'acme.app-dev.orbit')
            ->assertJsonPath('data.certificate_mode', CertificateMode::OrbitCa->value)
            ->assertJsonPath('data.status', LifecycleStatus::Active->value);

        $second = $this
            ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $this->node->id,
                'name' => 'renamed-metadata',
                'php_version' => '8.4',
            ]);

        $second
            ->assertOk()
            ->assertJsonPath('data.id', $first->json('data.id'))
            ->assertJsonPath('data.name', 'renamed-metadata')
            ->assertJsonPath('data.php_version', '8.4')
            ->assertJsonPath('data.status', 'active');

        expect(Instance::query()->count())
            ->toBe(1)
            ->and($this->runtime->calls)
            ->toBe(['instance:1:8.5', 'instance:1:8.4']);

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->subject_type)
            ->toBe(Instance::class)
            ->and($activity->subject_id)
            ->toBe($first->json('data.id'))
            ->and($activity->target_node_id)
            ->toBe($this->node->id);
    });

    it('marks a failed convergence and resumes it on retry', function (): void {
        $this->runtime->fail = true;
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $this->node->id,
                'name' => 'dev',
            ])
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'instance.php_fpm_failed');

        $instance = Instance::query()->sole();

        expect($instance->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($instance->failed_step)
            ->toBe('php-fpm')
            ->and($instance->error_code)
            ->toBe('instance.php_fpm_failed')
            ->and(Activity::query()->where('request_id', $requestId)->sole()->error_code)
            ->toBe('instance.php_fpm_failed');

        $this->runtime->fail = false;

        $this
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $this->node->id,
                'name' => 'dev',
            ])
            ->assertOk()
            ->assertJsonPath('data.status', 'active')
            ->assertJsonPath('data.failed_step', null)
            ->assertJsonPath('data.error_code', null);
    });

    it('requires an active app-dev role and permits one app placement on another node', function (): void {
        $otherNode = Node::query()->create([
            'name' => 'other',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.11',
            'wireguard_address' => '10.44.0.4',
        ]);

        $this
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $otherNode->id,
                'name' => 'other',
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'instance.node_not_app_dev');

        create_instance_for_api_test($this->orbitApp, $this->node);
        $otherNode
            ->roles()
            ->create([
                'role' => RoleName::AppDev,
                'status' => LifecycleStatus::Active,
            ]);

        $this
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $otherNode->id,
                'name' => 'other-node-metadata',
            ])
            ->assertCreated()
            ->assertJsonPath('data.name', 'other-node-metadata')
            ->assertJsonPath('data.checkout_path', '/home/orbit/apps/acme');

        expect(Instance::query()->count())->toBe(2);
    });

    it('lists, shows, changes php, and removes an instance', function (): void {
        $instance = create_instance_for_api_test($this->orbitApp, $this->node);

        $this
            ->getJson('/api/v1/instances')
            ->assertOk()
            ->assertJsonPath('data.0.id', $instance->id);
        $this
            ->getJson("/api/v1/instances/{$instance->id}")
            ->assertOk()
            ->assertJsonPath('data.name', 'dev');

        $this
            ->patchJson("/api/v1/instances/{$instance->id}/php", ['php_version' => '8.4'])
            ->assertOk()
            ->assertJsonPath('data.php_version', '8.4')
            ->assertJsonPath('data.status', 'active');

        $this
            ->deleteJson("/api/v1/instances/{$instance->id}")
            ->assertOk()
            ->assertJsonPath('data.id', $instance->id);

        expect(Instance::query()->count())
            ->toBe(0)
            ->and($this->runtime->calls)
            ->toContain('instance-remove:1');
    });

    it('does not remove an instance with workspaces', function (): void {
        $instance = create_instance_for_api_test($this->orbitApp, $this->node);
        $instance
            ->workspaces()
            ->create([
                'name' => 'feature',
                'branch' => 'feature',
                'checkout_path' => '/home/orbit/.orbit/worktrees/acme/feature',
                'hostname' => 'feature.acme.app-dev.orbit',
            ]);

        $this
            ->deleteJson("/api/v1/instances/{$instance->id}")
            ->assertConflict()
            ->assertJsonPath('error.code', 'instance.has_workspaces');
    });

    it('marks a failed removal so it can be resumed', function (): void {
        $instance = create_instance_for_api_test($this->orbitApp, $this->node);
        $this->runtime->fail = true;

        $this
            ->deleteJson("/api/v1/instances/{$instance->id}")
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'instance.remove_failed');

        expect($instance->fresh()?->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($instance->fresh()?->failed_step)
            ->toBe('instance-source-remove');
    });

    it('rejects unsafe document roots and php versions', function (array $payload, string $field): void {
        $this
            ->postJson('/api/v1/instances', [
                'app_id' => $this->orbitApp->id,
                'node_id' => $this->node->id,
                'name' => 'dev',
                ...$payload,
            ])
            ->assertUnprocessable()
            ->assertJsonPath("error.details.{$field}.0", fn (string $message): bool => $message !== '');
    })->with([
        'absolute document root' => [['document_root' => '/etc'], 'document_root'],
        'parent document root' => [['document_root' => '../public'], 'document_root'],
        'shell-like php version' => [['php_version' => '8.5;id'], 'php_version'],
        'unavailable php version' => [['php_version' => '9.9'], 'php_version'],
        'non-DNS instance name' => [['name' => 'dev_one'], 'name'],
    ]);
});

function create_instance_for_api_test(OrbitApp $app, Node $node): Instance
{
    return Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'dev',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/acme',
        'hostname' => 'acme.app-dev.orbit',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);
}
