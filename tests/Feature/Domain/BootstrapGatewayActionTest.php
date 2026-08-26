<?php

declare(strict_types=1);

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('initializes the portable gateway authority idempotently', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $web = new class implements GatewayWebConverger {
        /** @var list<array{hostname: string, address: string}> */
        public array $calls = [];

        public function converge(string $hostname, string $wireguardAddress): void
        {
            $this->calls[] = ['hostname' => $hostname, 'address' => $wireguardAddress];
        }
    };
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: new NativeProcessRunner,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: $web,
        orbitHome: $orbitHome,
    );
    $data = new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'test',
        privateInterface: 'eth3',
    );

    try {
        $first = $action->execute($data);
        $second = $action->execute($data);
        expect($first->is($second))
            ->toBeTrue()
            ->and($first->roles()->pluck('role')->all())
            ->toContain(RoleName::Gateway, RoleName::Vpn)
            ->and(is_file($orbitHome.'/ssh/id_ed25519'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/wireguard/private.key'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/ca/root.key'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/ca/root.pem'))
            ->toBeTrue()
            ->and(fileperms($orbitHome.'/ca/root.key') & 0o777)
            ->toBe(0o600)
            ->and(fileperms($orbitHome.'/ca/root.pem') & 0o777)
            ->toBe(0o644)
            ->and(fileperms($orbitHome.'/ca/root.lock') & 0o777)
            ->toBe(0o600)
            ->and(gateway_root_ca_pair_matches($orbitHome))
            ->toBeTrue()
            ->and(gateway_root_ca_validity_days($orbitHome))
            ->toBeIn([3649, 3650])
            ->and(app(VpnSettings::class)->privateInterface())
            ->toBe('eth3')
            ->and($web->calls)
            ->toBe([
                ['hostname' => 'gateway.test', 'address' => '10.44.0.1'],
                ['hostname' => 'gateway.test', 'address' => '10.44.0.1'],
            ])
            ->and(Node::query()->count())
            ->toBe(1);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('fails closed without mutating a partial root CA containing only :filename', function (
    string $filename,
    string $contents,
): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.(string) Str::uuid();
    mkdir(directory: $orbitHome.'/ssh', permissions: 0o700, recursive: true);
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    mkdir(directory: $orbitHome.'/ca', permissions: 0o700, recursive: true);
    file_put_contents($orbitHome.'/ssh/id_ed25519', data: 'private');
    file_put_contents($orbitHome.'/ssh/id_ed25519.pub', data: 'public');
    file_put_contents($orbitHome.'/wireguard/private.key', data: 'private');
    file_put_contents($orbitHome.'/wireguard/public.key', data: 'public');
    $partialPath = $orbitHome.'/ca/'.$filename;
    file_put_contents($partialPath, $contents);
    chmod(filename: $partialPath, permissions: 0o640);
    mkdir(directory: $orbitHome.'/ca/.root-ca.candidate', permissions: 0o700);
    file_put_contents($orbitHome.'/ca/.root-ca.candidate/root.key', data: 'stale-candidate');
    $processes = new class implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $invocations = [];

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocations[] = $invocation;

            return new CommandResult(1, '', 'unexpected process invocation', 1, false);
        }
    };
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: $processes,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: new class implements GatewayWebConverger {
            public function converge(string $hostname, string $wireguardAddress): void
            {
                throw new LogicException('Web convergence must not run after CA generation fails.');
            }
        },
        orbitHome: $orbitHome,
    );

    try {
        try {
            $action->execute(bootstrap_gateway_action_data());

            throw new LogicException('A partial root CA must fail closed.');
        } catch (NodeProvisioningException $exception) {
            expect($exception->step)
                ->toBe('ca-root-validate')
                ->and($exception->errorCode)
                ->toBe('ca.invalid_state')
                ->and($exception->getMessage())
                ->toContain('restore');
        }

        $missingFilename = $filename === 'root.key' ? 'root.pem' : 'root.key';

        expect(file_get_contents($partialPath))
            ->toBe($contents)
            ->and(fileperms($partialPath) & 0o777)
            ->toBe(0o640)
            ->and(is_file($orbitHome.'/ca/'.$missingFilename))
            ->toBeFalse()
            ->and(glob($orbitHome.'/ca/*.quarantine.*'))
            ->toBeEmpty()
            ->and(file_get_contents($orbitHome.'/ca/.root-ca.candidate/root.key'))
            ->toBe('stale-candidate')
            ->and($processes->invocations)
            ->toBeEmpty();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
})->with([
    'private key' => ['root.key', 'existing-private-key'],
    'certificate' => ['root.pem', "-----BEGIN CERTIFICATE-----\nexisting-certificate\n-----END CERTIFICATE-----\n"],
]);

it('rejects a mismatched complete root CA pair without replacing it', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $ca = $orbitHome.'/ca';
    mkdir(directory: $ca, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;
    $processes->run(new ProcessInvocation([
        'openssl',
        'genpkey',
        '-algorithm',
        'ED25519',
        '-out',
        $ca.'/root.key',
    ]));
    $processes->run(new ProcessInvocation([
        'openssl',
        'genpkey',
        '-algorithm',
        'ED25519',
        '-out',
        $ca.'/other.key',
    ]));
    $processes->run(new ProcessInvocation([
        'openssl',
        'req',
        '-x509',
        '-new',
        '-key',
        $ca.'/other.key',
        '-out',
        $ca.'/root.pem',
        '-days',
        '3650',
        '-subj',
        '/CN=Orbit Mismatched Root CA',
    ]));
    $originalKey = file_get_contents($ca.'/root.key');
    $originalCertificate = file_get_contents($ca.'/root.pem');
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: $processes,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: new class implements GatewayWebConverger {
            public function converge(string $hostname, string $wireguardAddress): void
            {
                throw new LogicException('Web convergence must not run for an invalid CA pair.');
            }
        },
        orbitHome: $orbitHome,
    );

    try {
        expect(fn () => $action->execute(bootstrap_gateway_action_data()))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('ca-root-validate')
                    ->and($exception->errorCode)
                    ->toBe('ca.invalid_state');
            });

        expect(file_get_contents($ca.'/root.key'))
            ->toBe($originalKey)
            ->and(file_get_contents($ca.'/root.pem'))
            ->toBe($originalCertificate);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('rejects an invalid static identity before persistence or host side effects', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $processes = new class implements ProcessRunner {
        public int $calls = 0;

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->calls++;

            return new CommandResult(0, '', '', 1, false);
        }
    };
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: $processes,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: new class implements GatewayWebConverger {
            public function converge(string $hostname, string $wireguardAddress): void
            {
                throw new LogicException('Web convergence must not run.');
            }
        },
        orbitHome: $orbitHome,
    );

    expect(fn () => $action->execute(new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'invalid domain',
    )))
        ->toThrow(InvalidArgumentException::class)
        ->and(Node::query()->count())
        ->toBe(0)
        ->and(is_dir($orbitHome))
        ->toBeFalse()
        ->and($processes->calls)
        ->toBe(0);
});

it('records provisioning and failed host convergence state and activates an idempotent retry', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $web = new class implements GatewayWebConverger {
        public bool $shouldFail = true;

        /** @var list<array{node: LifecycleStatus, roles: list<LifecycleStatus>}> */
        public array $observedStates = [];

        public function converge(string $hostname, string $wireguardAddress): void
        {
            $node = Node::query()->where('name', 'gateway')->firstOrFail();
            $this->observedStates[] = [
                'node' => $node->status,
                'roles' => $node->roles()->orderBy('role')->pluck('status')->all(),
            ];

            if ($this->shouldFail) {
                throw new NodeProvisioningException(
                    step: 'gateway-caddy-validate',
                    errorCode: 'gateway.caddy_config_invalid',
                    message: 'Simulated aggregate candidate failure.',
                );
            }
        }
    };
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: new NativeProcessRunner,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: $web,
        orbitHome: $orbitHome,
    );
    $data = new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'orbit',
    );

    try {
        expect(fn () => $action->execute($data))
            ->toThrow(NodeProvisioningException::class);

        $failed = Node::query()->where('name', 'gateway')->firstOrFail();

        expect($web->observedStates[0])
            ->toBe([
                'node' => LifecycleStatus::Provisioning,
                'roles' => [LifecycleStatus::Provisioning, LifecycleStatus::Provisioning],
            ])
            ->and($failed->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($failed->failed_step)
            ->toBe('gateway-caddy-validate')
            ->and($failed->error_code)
            ->toBe('gateway.caddy_config_invalid')
            ->and($failed->roles()->pluck('status')->all())
            ->each->toBe(LifecycleStatus::Failed)->and($failed->roles()->pluck('failed_step')->all())
            ->each->toBe('gateway-caddy-validate');

        $web->shouldFail = false;
        $active = $action->execute($data);

        expect($active->is($failed))
            ->toBeTrue()
            ->and($active->status)
            ->toBe(LifecycleStatus::Active)
            ->and($active->failed_step)
            ->toBeNull()
            ->and($active->roles()->pluck('status')->all())
            ->each
            ->toBe(LifecycleStatus::Active)
            ->and(Node::query()->count())
            ->toBe(1);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('records stable gateway failure state when bootstrap throws an unexpected exception', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        identity: new App\Actions\Gateway\GatewayBootstrapIdentityValidator,
        vpnSettings: app(VpnSettings::class),
        processes: new NativeProcessRunner,
        files: new ProtectedFileWriter,
        vpn: gateway_vpn_noop(),
        web: new class implements GatewayWebConverger {
            public function converge(string $hostname, string $wireguardAddress): void
            {
                throw new RuntimeException('Unexpected gateway web failure.');
            }
        },
        orbitHome: $orbitHome,
    );
    $data = new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'orbit',
    );

    try {
        expect(fn () => $action->execute($data))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('unknown')
                    ->and($exception->errorCode)
                    ->toBe('gateway.bootstrap_failed')
                    ->and($exception->getPrevious())
                    ->toBeInstanceOf(RuntimeException::class);
            });

        $failed = Node::query()->where('name', 'gateway')->firstOrFail();

        expect($failed->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($failed->failed_step)
            ->toBe('unknown')
            ->and($failed->error_code)
            ->toBe('gateway.bootstrap_failed')
            ->and($failed->roles()->count())
            ->toBe(2)
            ->and($failed->roles()->pluck('status')->all())
            ->each->toBe(LifecycleStatus::Failed)->and($failed->roles()->pluck('failed_step')->all())
            ->each->toBe('unknown')->and($failed->roles()->pluck('error_code')->all())
            ->each->toBe('gateway.bootstrap_failed');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

function gateway_vpn_noop(): GatewayVpnConverger
{
    return new class implements GatewayVpnConverger {
        public function converge(Node $gateway, BootstrapGatewayData $data): void {}
    };
}

function bootstrap_gateway_action_data(): BootstrapGatewayData
{
    return new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'orbit',
    );
}

function gateway_root_ca_pair_matches(string $orbitHome): bool
{
    $processes = new NativeProcessRunner;
    $certificatePublicKey = $processes->run(new ProcessInvocation([
        'openssl',
        'x509',
        '-in',
        $orbitHome.'/ca/root.pem',
        '-pubkey',
        '-noout',
    ]));
    $privatePublicKey = $processes->run(new ProcessInvocation([
        'openssl',
        'pkey',
        '-in',
        $orbitHome.'/ca/root.key',
        '-pubout',
    ]));

    return (
        $certificatePublicKey->succeeded()
        && $privatePublicKey->succeeded()
        && trim($certificatePublicKey->stdout) === trim($privatePublicKey->stdout)
    );
}

function gateway_root_ca_validity_days(string $orbitHome): int
{
    $dates = new NativeProcessRunner()->run(new ProcessInvocation([
        'openssl',
        'x509',
        '-in',
        $orbitHome.'/ca/root.pem',
        '-noout',
        '-dates',
    ]))->stdout;
    $notBefore = [];
    $notAfter = [];
    preg_match('/notBefore=(.+)/', $dates, $notBefore);
    preg_match('/notAfter=(.+)/', $dates, $notAfter);
    $startsAt = new DateTimeImmutable($notBefore[1]);
    $expiresAt = new DateTimeImmutable($notAfter[1]);
    $days = $startsAt->diff($expiresAt)->days;

    return is_int($days) ? $days : 0;
}
