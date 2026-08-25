<?php

declare(strict_types=1);

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Domain\Shared\LifecycleStatus;
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
        settings: app(SettingRepository::class),
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
        $scope = new SettingScope(SettingScopeType::Gateway);

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
            ->and(app(SettingRepository::class)->get($scope, 'vpn.private_interface'))
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
        settings: app(SettingRepository::class),
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
        settings: app(SettingRepository::class),
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
        settings: app(SettingRepository::class),
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
