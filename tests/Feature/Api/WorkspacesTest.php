<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

/** @mago-expect lint:halstead The shared fixture keeps all workspace API state transitions consistent. */
describe('workspace API', function (): void {
    beforeEach(function (): void {
        $this->runtime = new class implements AppDevRuntimeConverger {
            /** @var list<string> */
            public array $calls = [];

            public bool $fail = false;

            public function convergeInstance(Instance $instance): void {}

            public function removeInstance(Instance $instance): void {}

            public function convergeWorkspace(Workspace $workspace): void
            {
                $this->calls[] = "workspace:{$workspace->id}:{$workspace->php_version}";

                if ($this->fail) {
                    throw new RuntimeConvergenceException(
                        step: 'git-worktree',
                        errorCode: 'workspace.worktree_failed',
                        message: 'Worktree failed.',
                    );
                }
            }

            public function removeWorkspace(Workspace $workspace): void
            {
                $this->calls[] = "workspace-remove:{$workspace->id}";

                if ($this->fail) {
                    throw new RuntimeConvergenceException(
                        step: 'workspace-source-remove',
                        errorCode: 'workspace.remove_failed',
                        message: 'Workspace removal failed.',
                    );
                }
            }
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
        $app = OrbitApp::query()->create([
            'name' => 'Acme',
            'slug' => 'acme',
            'repository_url' => 'git@github.com:acme/site.git',
        ]);
        $this->instance = Instance::query()->create([
            'app_id' => $app->id,
            'node_id' => $this->node->id,
            'name' => 'dev',
            'environment' => 'development',
            'checkout_path' => '/home/orbit/apps/acme',
            'hostname' => 'acme.app-dev.orbit',
            'certificate_mode' => CertificateMode::OrbitCa,
            'status' => LifecycleStatus::Active,
        ]);
    });

    it('creates a workspace with default branch, path, hostname, and inherited php', function (): void {
        $requestId = (string) \Illuminate\Support\Str::uuid();
        $response = $this->withHeader('X-Orbit-Request-Id', $requestId)->postJson('/api/v1/workspaces', [
            'instance_id' => $this->instance->id,
            'name' => 'feature-one',
        ]);

        $response
            ->assertCreated()
            ->assertJsonPath('data.branch', 'feature-one')
            ->assertJsonPath('data.checkout_path', '/home/orbit/.orbit/worktrees/acme/feature-one')
            ->assertJsonPath('data.php_version', null)
            ->assertJsonPath('data.effective_php_version', '8.5')
            ->assertJsonPath('data.hostname', 'feature-one.acme.app-dev.orbit')
            ->assertJsonPath('data.status', 'active');

        expect($this->runtime->calls)->toBe(['workspace:1:']);

        $activity = \App\Models\Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->subject_type)
            ->toBe(Workspace::class)
            ->and($activity->subject_id)
            ->toBe($response->json('data.id'))
            ->and($activity->target_node_id)
            ->toBe($this->node->id);
    });

    it('accepts a safe absolute checkout path and resumes failed convergence', function (): void {
        $this->runtime->fail = true;

        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-one',
                'branch' => 'feature/one',
                'checkout_path' => '/home/orbit/custom-worktrees/acme-feature-one',
                'php_version' => '8.4',
            ])
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'workspace.worktree_failed');

        expect(Workspace::query()->sole()->status)->toBe(LifecycleStatus::Failed);

        $this->runtime->fail = false;

        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-one',
                'branch' => 'feature/one',
                'checkout_path' => '/home/orbit/custom-worktrees/acme-feature-one',
                'php_version' => '8.4',
            ])
            ->assertOk()
            ->assertJsonPath('data.status', 'active')
            ->assertJsonPath('data.checkout_path', '/home/orbit/custom-worktrees/acme-feature-one');
    });

    it('lists, shows, changes php, and removes a workspace', function (): void {
        $workspace = create_workspace_for_api_test($this->instance);

        $this
            ->getJson('/api/v1/workspaces')
            ->assertOk()
            ->assertJsonPath('data.0.id', $workspace->id);
        $this
            ->getJson("/api/v1/workspaces/{$workspace->id}")
            ->assertOk()
            ->assertJsonPath('data.name', 'feature-one');

        $this
            ->patchJson("/api/v1/workspaces/{$workspace->id}/php", ['php_version' => '8.4'])
            ->assertOk()
            ->assertJsonPath('data.php_version', '8.4')
            ->assertJsonPath('data.effective_php_version', '8.4');

        $this
            ->deleteJson("/api/v1/workspaces/{$workspace->id}")
            ->assertOk()
            ->assertJsonPath('data.id', $workspace->id);

        expect(Workspace::query()->count())
            ->toBe(0)
            ->and($this->runtime->calls)
            ->toContain('workspace-remove:1');
    });

    it('deletes a workspace before releasing its per-node source lock', function (): void {
        $workspace = create_workspace_for_api_test($this->instance);
        $lock = new class($workspace) implements AppDevSourceOperationLock {
            public int $calls = 0;

            public bool $workspaceWasDeletedBeforeRelease = false;

            public function __construct(
                private readonly Workspace $workspace,
            ) {}

            public function synchronized(int $nodeId, Closure $operation): mixed
            {
                $this->calls++;
                $result = $operation();
                $this->workspaceWasDeletedBeforeRelease = ! Workspace::query()
                    ->whereKey($this->workspace->id)
                    ->exists();

                return $result;
            }
        };
        app()->instance(AppDevSourceOperationLock::class, $lock);

        $this
            ->deleteJson("/api/v1/workspaces/{$workspace->id}")
            ->assertOk();

        expect($lock->calls)
            ->toBe(1)
            ->and($lock->workspaceWasDeletedBeforeRelease)
            ->toBeTrue();
    });

    it('does not let two managed checkouts overlap on one node', function (): void {
        create_workspace_for_api_test($this->instance);

        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-two',
                'checkout_path' => '/home/orbit/.orbit/worktrees/acme/feature-one/nested',
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'workspace.path_taken');

        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-three',
                'checkout_path' => '/home/orbit/apps/acme',
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        expect(Workspace::query()->count())
            ->toBe(1)
            ->and($this->runtime->calls)
            ->toBeEmpty();
    });

    it('rejects branch drift when resuming a workspace', function (): void {
        create_workspace_for_api_test($this->instance);

        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-one',
                'branch' => 'other-branch',
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'workspace.branch_change_unsupported');

        expect($this->runtime->calls)->toBeEmpty();
    });

    it('rejects unsafe paths and branch names', function (array $payload, string $field): void {
        $this
            ->postJson('/api/v1/workspaces', [
                'instance_id' => $this->instance->id,
                'name' => 'feature-one',
                ...$payload,
            ])
            ->assertUnprocessable()
            ->assertJsonPath("error.details.{$field}.0", fn (string $message): bool => $message !== '');
    })->with([
        'relative path' => [['checkout_path' => '../worktree'], 'checkout_path'],
        'system path' => [['checkout_path' => '/etc/orbit'], 'checkout_path'],
        'parent segment' => [['checkout_path' => '/home/orbit/worktrees/../escape'], 'checkout_path'],
        'dot segment' => [['checkout_path' => '/home/orbit/worktrees/./feature'], 'checkout_path'],
        'repeated separator' => [['checkout_path' => '/home/orbit/worktrees//feature'], 'checkout_path'],
        'trailing separator' => [['checkout_path' => '/home/orbit/worktrees/feature/'], 'checkout_path'],
        'SSH directory' => [['checkout_path' => '/home/orbit/.ssh/feature'], 'checkout_path'],
        'Orbit SSH directory' => [['checkout_path' => '/home/orbit/.orbit/ssh/feature'], 'checkout_path'],
        'app directory' => [['checkout_path' => '/home/orbit/apps/other/feature'], 'checkout_path'],
        'option branch' => [['branch' => '--upload-pack=bad'], 'branch'],
        'invalid php version' => [['php_version' => 'latest'], 'php_version'],
        'unavailable php version' => [['php_version' => '9.9'], 'php_version'],
        'non-DNS workspace name' => [['name' => 'feature_one'], 'name'],
    ]);

    it('marks a failed removal so it can be resumed', function (): void {
        $workspace = create_workspace_for_api_test($this->instance);
        $this->runtime->fail = true;

        $this
            ->deleteJson("/api/v1/workspaces/{$workspace->id}")
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'workspace.remove_failed');

        expect($workspace->fresh()?->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($workspace->fresh()?->failed_step)
            ->toBe('workspace-source-remove');
    });
});

function create_workspace_for_api_test(Instance $instance): Workspace
{
    return Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'feature-one',
        'branch' => 'feature-one',
        'checkout_path' => '/home/orbit/.orbit/worktrees/acme/feature-one',
        'hostname' => 'feature-one.acme.app-dev.orbit',
        'status' => LifecycleStatus::Active,
    ]);
}
