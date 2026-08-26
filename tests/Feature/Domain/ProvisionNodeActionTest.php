<?php

declare(strict_types=1);

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\ProvisionNodeData;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProjectionOperationLock;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Models\App;
use App\Models\Node;

/** @mago-expect lint:halstead The shared DNS fake keeps node lifecycle transitions observable. */
describe(ProvisionNodeAction::class, function (): void {
    beforeEach(function (): void {
        $this->privateDns = new class implements PrivateDnsManager {
            public int $calls = 0;

            public ?Throwable $failure = null;

            public ?LifecycleStatus $pendingStatus = null;

            public ?int $pendingNodeId = null;

            public function converge(?Node $pendingNode = null): void
            {
                $this->calls++;
                $this->pendingStatus = $pendingNode?->status;
                $this->pendingNodeId = $pendingNode?->id;

                if ($this->failure instanceof Throwable) {
                    throw $this->failure;
                }
            }
        };
        app()->instance(PrivateDnsManager::class, $this->privateDns);
        $this->peers = new class implements GatewayPeerProjectionManager {
            public int $convergences = 0;

            public ?Throwable $failure = null;

            public function converge(Node $node): void
            {
                $this->convergences++;

                if ($this->failure instanceof Throwable) {
                    throw $this->failure;
                }
            }

            public function remove(Node $node): void {}

            public function restore(Node $node): void {}
        };
        app()->instance(GatewayPeerProjectionManager::class, $this->peers);
    });

    it('holds the global projection lock through convergence', function (): void {
        $lock = new class implements NodeProjectionOperationLock {
            public bool $held = false;

            public int $calls = 0;

            public function synchronized(Closure $operation): mixed
            {
                $this->calls++;
                $this->held = true;

                try {
                    return $operation();
                } finally {
                    $this->held = false;
                }
            }
        };
        $converger = new class(static fn (): bool => $lock->held) implements NodeConverger {
            public bool $observedLock = false;

            public function __construct(
                private Closure $lockIsHeld,
            ) {}

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->observedLock = ($this->lockIsHeld)();
            }
        };
        app()->instance(NodeProjectionOperationLock::class, $lock);
        app()->instance(NodeConverger::class, $converger);

        app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'locked-node',
            publicSshHost: '192.0.2.70',
            architecture: 'x86_64',
            expectedSshHostFingerprint: 'SHA256:pinned',
        ));

        expect($lock->calls)
            ->toBe(1)
            ->and($converger->observedLock)
            ->toBeTrue();
    });

    it('activates a node after its requested roles converge', function (): void {
        $converger = new class implements NodeConverger {
            public ?string $expectedFingerprint = null;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;
            }
        };
        app()->instance(NodeConverger::class, $converger);

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
            ->and($this->privateDns->pendingStatus)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($this->privateDns->pendingNodeId)
            ->toBe($node->id);
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
            ->and($this->privateDns->calls)
            ->toBe(1);
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
            ->toBe(0)
            ->and($this->privateDns->calls)
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

        expect($converger->calls)
            ->toBe(0)
            ->and($this->privateDns->calls)
            ->toBe(0);
    });

    it('keeps a Darwin app-dev registration provisioning for local setup', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        $node = app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'mac-dev',
            publicSshHost: '10.44.0.8',
            roles: [RoleName::AppDev],
            platform: 'darwin',
            architecture: 'arm64',
            tld: 'mac.test',
            sshUser: 'nckrtl',
            wireguardPublicKey: base64_encode(str_repeat(string: "\x01", times: 32)),
        ));

        expect($node->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($node->ssh_host_fingerprint)
            ->toBeNull()
            ->and($converger->calls)
            ->toBe(0)
            ->and($this->privateDns->calls)
            ->toBe(1)
            ->and($this->peers->convergences)
            ->toBe(1);
    });

    it('retains a failed peer projection and resumes an identical Darwin enrollment retry', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        $data = new ProvisionNodeData(
            name: 'retry-mini',
            publicSshHost: '',
            roles: [RoleName::AppDev],
            platform: 'darwin',
            architecture: 'arm64',
            tld: 'retry.test',
            sshUser: 'nckrtl',
            wireguardPublicKey: base64_encode(str_repeat(string: "\x02", times: 32)),
        );
        $this->peers->failure = new RuntimeException('projection failed');

        expect(fn (): Node => app(ProvisionNodeAction::class)->execute($data))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-projection')
                    ->and($exception->errorCode)
                    ->toBe('node.wireguard_projection_failed');
            });

        $failed = Node::query()->where('name', 'retry-mini')->sole();

        expect($failed->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($failed->roles()->sole()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($this->privateDns->calls)
            ->toBe(0);

        $this->peers->failure = null;
        $retried = app(ProvisionNodeAction::class)->execute($data);

        expect($retried->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($retried->failed_step)
            ->toBeNull()
            ->and($retried->roles()->sole()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($this->peers->convergences)
            ->toBe(2)
            ->and($this->privateDns->calls)
            ->toBe(1);
    });

    it('rejects protected Darwin setup input drift before state or projection mutation', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        $publicKey = base64_encode(str_repeat(string: "\x03", times: 32));
        $node = Node::query()->create([
            'name' => 'protected-mini',
            'status' => LifecycleStatus::Active,
            'platform' => 'darwin',
            'architecture' => 'arm64',
            'tld' => 'protected.test',
            'public_ssh_host' => '10.44.0.8',
            'ssh_user' => 'nckrtl',
            'wireguard_address' => '10.44.0.8',
            'wireguard_public_key' => $publicKey,
        ]);
        $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);

        expect(fn (): Node => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'protected-mini',
            publicSshHost: '10.44.0.8',
            roles: [RoleName::AppDev],
            platform: 'darwin',
            architecture: 'x86_64',
            tld: 'protected.test',
            sshUser: 'nckrtl',
            wireguardAddress: '10.44.0.8',
            wireguardPublicKey: $publicKey,
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)
                ->toBe('node.protected_state_changed')
                ->and($exception->status)
                ->toBe(409);
        });

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($node->architecture)
            ->toBe('arm64')
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($this->peers->convergences)
            ->toBe(0)
            ->and($this->privateDns->calls)
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

    it('requires the real architecture for Darwin registration', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'mac-dev',
            publicSshHost: '10.44.0.8',
            roles: [RoleName::AppDev],
            platform: 'darwin',
            tld: 'mac.test',
            sshUser: 'nckrtl',
            wireguardPublicKey: base64_encode(str_repeat(string: "\x01", times: 32)),
        )))->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('node.architecture_required');
        });

        expect(Node::query()->where('name', 'mac-dev')->exists())->toBeFalse();
    });

    it('marks the node and roles failed when private DNS projection fails', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        $this->privateDns->failure = new RuntimeException('dnsmasq failed');

        expect(fn () => app(ProvisionNodeAction::class)->execute(new ProvisionNodeData(
            name: 'app-dev',
            publicSshHost: '94.237.40.75',
            roles: [RoleName::AppDev],
            architecture: 'x86_64',
            tld: 'app-dev.orbit',
            expectedSshHostFingerprint: 'SHA256:pinned',
        )))->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('private-dns')
                ->and($exception->errorCode)
                ->toBe('node.dns_projection_failed');
        });

        $node = Node::query()->where('name', 'app-dev')->sole();

        expect($node->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->failed_step)
            ->toBe('private-dns')
            ->and($node->error_code)
            ->toBe('node.dns_projection_failed');
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
            ->toBe('node.package_install_failed');
    });
});
