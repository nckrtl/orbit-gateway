<?php

declare(strict_types=1);

use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\WireGuard\NativeGatewayVpnConverger;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

it('activates the gateway WireGuard address through a validated atomic server config', function (): void {
    [$converger, $processes, $orbitHome] = gateway_vpn_converger();
    $node = Node::query()->create([
        'name' => 'gateway',
        'public_ssh_host' => '85.9.218.89',
        'wireguard_address' => '10.44.0.1',
    ]);

    try {
        $converger->converge($node, gateway_bootstrap_data());

        expect(file_get_contents($orbitHome.'/generated/wireguard/orbit.conf'))
            ->toContain(
                'Address = 10.44.0.1/24',
                'ListenPort = 51820',
                'PrivateKey = SERVER_PRIVATE',
            )
            ->not
            ->toContain('[Peer]')
            ->and(
                Collection::make($processes->calls)
                    ->map(static fn (ProcessInvocation $call): array => $call->arguments)
                    ->all(),
            )
            ->toBe([
                [
                    'sudo',
                    'install',
                    '-D',
                    '-o',
                    'root',
                    '-g',
                    'root',
                    '-m',
                    '0600',
                    '--',
                    $orbitHome.'/generated/wireguard/orbit.conf',
                    '/etc/wireguard/orbit-candidate.conf',
                ],
                ['sudo', 'wg-quick', 'strip', '/etc/wireguard/orbit-candidate.conf'],
                [
                    'sudo',
                    'mv',
                    '-f',
                    '--',
                    '/etc/wireguard/orbit-candidate.conf',
                    '/etc/wireguard/orbit.conf',
                ],
                ['sudo', 'systemctl', 'enable', 'wg-quick@orbit'],
                ['sudo', 'systemctl', 'restart', 'wg-quick@orbit'],
            ]);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('does not replace or start the gateway WireGuard service when validation fails', function (): void {
    [$converger, $processes, $orbitHome] = gateway_vpn_converger(failValidation: true);
    $node = Node::query()->create([
        'name' => 'gateway',
        'public_ssh_host' => '85.9.218.89',
        'wireguard_address' => '10.44.0.1',
    ]);

    try {
        expect(fn () => $converger->converge($node, gateway_bootstrap_data()))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-server-validate')
                    ->and($exception->errorCode)
                    ->toBe('vpn.server_config_invalid');
            });
        $commands = Collection::make($processes->calls)
            ->map(static fn (ProcessInvocation $call): array => $call->arguments);

        expect($commands->contains(
            static fn (array $arguments): bool => end($arguments) === '/etc/wireguard/orbit.conf',
        ))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'systemctl', 'restart', 'wg-quick@orbit']))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'rm', '-f', '--', '/etc/wireguard/orbit-candidate.conf']))
            ->toBeTrue();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

/** @return array{NativeGatewayVpnConverger, object&ProcessRunner, string} */
function gateway_vpn_converger(bool $failValidation = false): array
{
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(filename: $orbitHome.'/wireguard/private.key', data: 'SERVER_PRIVATE');
    file_put_contents(filename: $orbitHome.'/wireguard/public.key', data: 'SERVER_PUBLIC');
    $processes = new class($failValidation) implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $calls = [];

        public function __construct(
            private readonly bool $failValidation,
        ) {}

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->calls[] = $invocation;

            if (
                $this->failValidation
                && $invocation->arguments === ['sudo', 'wg-quick', 'strip', '/etc/wireguard/orbit-candidate.conf']
            ) {
                return new CommandResult(1, '', 'invalid WireGuard config', 2, false);
            }

            return new CommandResult(0, '', '', 2, false);
        }
    };

    return [
        new NativeGatewayVpnConverger(
            renderer: new \App\Infrastructure\WireGuard\WireGuardServerConfigRenderer,
            files: new ProtectedFileWriter,
            processes: $processes,
            orbitHome: $orbitHome,
        ),
        $processes,
        $orbitHome,
    ];
}

function gateway_bootstrap_data(): BootstrapGatewayData
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
