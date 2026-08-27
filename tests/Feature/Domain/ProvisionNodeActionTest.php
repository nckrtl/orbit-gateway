<?php

declare(strict_types=1);

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\ProvisionNodeData;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\App;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Facades\DB;

/** @mago-expect lint:halstead The provisioning group keeps ordering and failure boundaries visible. */
describe(ProvisionNodeAction::class, function (): void {
    beforeEach(function (): void {
        app()->instance(RoleBaselineConverger::class, new class implements RoleBaselineConverger {
            public function converge(Node $node, NodeRole $assignment): void {}

            public function remove(Node $node, NodeRole $assignment, bool $purgeData): void {}
        });
    });

    it('activates a node after its requested roles converge', function (): void {
        $events = [];
        $converger = new class($events) implements NodeConverger {
            public ?string $expectedFingerprint = null;

            /** @param list<string> $events */
            public function __construct(
                private array &$events,
            ) {}

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;
                $this->events[] = "base:{$node->status->value}:{$node->roles()->count()}";
            }
        };
        app()->instance(NodeConverger::class, $converger);
        app()->instance(RoleBaselineConverger::class, new class($events) implements RoleBaselineConverger {
            /** @param list<string> $events */
            public function __construct(
                private array &$events,
            ) {}

            public function converge(Node $node, NodeRole $assignment): void
            {
                $this->events[] = "role:{$assignment->role->value}:{$node->status->value}:".DB::transactionLevel();
            }

            public function remove(Node $node, NodeRole $assignment, bool $purgeData): void {}
        });

        $ambientTransactionLevel = DB::transactionLevel();
        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            platform: 'linux',
            architecture: 'x86_64',
            tld: '.App-Dev.Orbit',
            expectedSshHostFingerprint: 'SHA256:pinned',
        ));

        expect($node->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->platform)
            ->toBe('linux')
            ->and($node->architecture)
            ->toBe('x86_64')
            ->and($node->tld)
            ->toBe('app-dev.orbit')
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($converger->expectedFingerprint)
            ->toBe('SHA256:pinned')
            ->and($events)
            ->toBe(['base:provisioning:0', "role:app-dev:active:{$ambientTransactionLevel}"]);
    });

    it('rejects pairwise requested role conflicts before persistence or base convergence', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'conflicted',
            publicSshHost: '192.0.2.80',
            roles: [RoleName::AppDev, RoleName::AppProd],
            architecture: 'x86_64',
            tld: 'conflicted.orbit',
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))
            ->toThrow(RoleAssignmentException::class);

        expect($converger->calls)
            ->toBe(0)
            ->and(Node::query()->where('name', 'conflicted')->exists())
            ->toBeFalse();
    });

    it('reconverges requested existing roles and leaves omitted roles untouched', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        $roles = [];
        app()->instance(RoleBaselineConverger::class, new class($roles) implements RoleBaselineConverger {
            /** @param list<RoleName> $roles */
            public function __construct(
                private array &$roles,
            ) {}

            public function converge(Node $node, NodeRole $assignment): void
            {
                $this->roles[] = $assignment->role;
            }

            public function remove(Node $node, NodeRole $assignment, bool $purgeData): void {}
        });
        $node = Node::query()->create([
            'name' => 'existing-host',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'tld' => 'existing.orbit',
            'public_ssh_host' => '192.0.2.81',
            'wireguard_address' => '10.44.0.8',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $requested = $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);
        $omitted = $node->roles()->create([
            'role' => RoleName::Vpn,
            'status' => LifecycleStatus::Failed,
            'failed_step' => 'converge:dnsmasq',
            'error_code' => 'vpn.dnsmasq_failed',
        ]);

        app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'existing-host',
            publicSshHost: '192.0.2.81',
            roles: [RoleName::AppDev],
        ));

        expect($roles)
            ->toBe([RoleName::AppDev])
            ->and($requested->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($omitted->refresh()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($omitted->failed_step)
            ->toBe('converge:dnsmasq')
            ->and($omitted->error_code)
            ->toBe('vpn.dnsmasq_failed');
    });

    it('passes the operator expected pin without storing it as the observed fingerprint', function (): void {
        $converger = new class implements NodeConverger {
            public ?string $expectedFingerprint = null;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $expectedFingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'roleless-operator',
            publicSshHost: '192.0.2.61',
            expectedSshHostFingerprint: $expectedFingerprint,
            architecture: 'x86_64',
        ));

        expect($converger->expectedFingerprint)
            ->toBe($expectedFingerprint)
            ->and($node->ssh_host_fingerprint)
            ->toBeNull();
    });

    it('preserves an existing app-dev TLD when provisioning omits it', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        Node::query()->create([
            'name' => 'app-dev',
            'architecture' => 'x86_64',
            'public_ssh_host' => '94.237.40.75',
            'tld' => 'app-dev.orbit',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
        ));

        expect($node->tld)->toBe('app-dev.orbit');
    });

    it('preserves established node identity and connection fields during safe reprovision', function (): void {
        $converger = new class implements NodeConverger {
            /** @var array<string, mixed> */
            public array $observed = [];

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->observed = $node->only([
                    'platform',
                    'architecture',
                    'public_ssh_port',
                    'ssh_user',
                    'wireguard_endpoint_override',
                    'dns_server_override',
                ]);
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $existing = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'aarch64',
            'tld' => 'app-dev.orbit',
            'public_ssh_host' => '192.0.2.20',
            'public_ssh_port' => 2222,
            'ssh_user' => 'orbit',
            'wireguard_address' => '10.44.0.3',
            'wireguard_endpoint_override' => '10.0.0.2:51820',
            'dns_server_override' => '10.0.0.1',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $existing->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '192.0.2.20',
        ));

        expect($converger->observed)
            ->toBe([
                'platform' => 'linux',
                'architecture' => 'aarch64',
                'public_ssh_port' => 2222,
                'ssh_user' => 'orbit',
                'wireguard_endpoint_override' => '10.0.0.2:51820',
                'dns_server_override' => '10.0.0.1',
            ])
            ->and($node->tld)
            ->toBe('app-dev.orbit')
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active);
    });

    it('rejects a TLD change while the node owns instances', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $node = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'tld' => 'app-dev.orbit',
            'public_ssh_host' => '192.0.2.20',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);
        $app = App::query()->create([
            'name' => 'Orbit',
            'slug' => 'orbit',
            'repository_url' => 'git@example.test:orbit.git',
        ]);
        $node->instances()->create([
            'app_id' => $app->id,
            'name' => 'main',
            'environment' => 'development',
            'checkout_path' => '/home/orbit/apps/orbit/main',
            'hostname' => 'main.app-dev.orbit',
            'certificate_mode' => 'orbit-ca',
        ]);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '192.0.2.20',
            tld: 'changed.orbit',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)
                ->toBe('node.tld_change_unsupported')
                ->and($exception->status)
                ->toBe(409);
        });

        expect($node->refresh()->tld)
            ->toBe('app-dev.orbit')
            ->and($converger->calls)
            ->toBe(0);
    });

    it('requires a TLD when the node already owns the app-dev role', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $node = Node::query()->create([
            'name' => 'existing-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'public_ssh_host' => '192.0.2.30',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'existing-dev',
            publicSshHost: '192.0.2.30',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.tld_required');
        });

        expect($converger->calls)->toBe(0);
    });

    it('rejects non-Linux nodes before persistence or convergence', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'mac-dev',
            publicSshHost: '10.44.0.8',
            roles: [RoleName::AppDev],
            platform: 'windows',
            architecture: 'arm64',
            tld: 'mac.test',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.platform_unsupported');
        });

        expect(Node::query()->where('name', 'mac-dev')->exists())
            ->toBeFalse()
            ->and($converger->calls)
            ->toBe(0);
    });

    it('requires the real architecture for a new Linux registration', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'linux-node',
            publicSshHost: '192.0.2.60',
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.architecture_required');
        });

        expect(Node::query()->where('name', 'linux-node')->exists())->toBeFalse();
    });

    it('keeps the node active when initial role convergence fails', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        app()->instance(RoleBaselineConverger::class, new class implements RoleBaselineConverger {
            public function converge(Node $node, NodeRole $assignment): void
            {
                throw new RuntimeConvergenceException(
                    step: 'caddy-config',
                    errorCode: 'app-dev.caddy_config_failed',
                    message: 'Caddy failed.',
                );
            }

            public function remove(Node $node, NodeRole $assignment, bool $purgeData): void {}
        });

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            architecture: 'x86_64',
            tld: 'app-dev.orbit',
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))->toThrow(function (NodeRoleOperationException $exception): void {
            expect($exception->step)
                ->toBe('converge:caddy-config')
                ->and($exception->errorCode)
                ->toBe('node_role.convergence_failed');
        });

        $node = Node::query()->where('name', 'app-dev')->sole();

        expect($node->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->failed_step)
            ->toBeNull()
            ->and($node->error_code)
            ->toBeNull()
            ->and($node->roles()->sole()->failed_step)
            ->toBe('converge:caddy-config')
            ->and($node->roles()->sole()->error_code)
            ->toBe('app-dev.caddy_config_failed');
    });

    it('rejects duplicate app-dev TLD ownership before convergence', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);
        Node::query()->create([
            'name' => 'first-dev',
            'public_ssh_host' => '192.0.2.50',
            'tld' => 'test',
        ]);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'second-dev',
            publicSshHost: '192.0.2.51',
            roles: [RoleName::AppDev],
            architecture: 'x86_64',
            tld: '.TEST',
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)
                ->toBe('node.tld_taken')
                ->and($exception->status)
                ->toBe(409);
        });

        expect($converger->calls)->toBe(0);
    });

    it('requires a first-contact fingerprint before persisting a node', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            architecture: 'x86_64',
            tld: 'app-dev.orbit',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.ssh_host_fingerprint_required');
        });

        expect(Node::query()->where('name', 'app-dev')->exists())
            ->toBeFalse()
            ->and($converger->calls)
            ->toBe(0);
    });

    it('rejects an unsafe WireGuard endpoint override before persisting a node', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'unsafe-endpoint',
            publicSshHost: '192.0.2.46',
            wireguardEndpointOverride: "10.0.0.2:51820\nPostUp = touch /tmp/orbit-injected",
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('vpn.endpoint_override_invalid');
        });

        expect(Node::query()->where('name', 'unsafe-endpoint')->exists())->toBeFalse();
    });

    it('stores the failed step and stable error code', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                throw new NodeProvisioningException('base-packages', 'node.package_install_failed', 'Apt failed.');
            }
        });
        $action = app(ProvisionNodeAction::class);
        $data = new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            architecture: 'x86_64',
            tld: 'app-dev.orbit',
            expectedSshHostFingerprint: 'SHA256:pinned',
        );

        expect(fn () => $action->execute($data))->toThrow(NodeProvisioningException::class, 'Apt failed.');

        $node = Node::query()->where('name', 'app-dev')->sole();

        expect($node->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->failed_step)
            ->toBe('base-packages')
            ->and($node->error_code)
            ->toBe('node.package_install_failed')
            ->and($node->roles()->exists())
            ->toBeFalse();
    });
});
