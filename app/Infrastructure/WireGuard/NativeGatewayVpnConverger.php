<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;

final readonly class NativeGatewayVpnConverger implements GatewayVpnConverger
{
    private const string CANDIDATE_CONFIG = '/etc/wireguard/orbit-candidate.conf';

    private const string LIVE_CONFIG = '/etc/wireguard/orbit.conf';

    public function __construct(
        private WireGuardServerConfigRenderer $renderer,
        private ProtectedFileWriter $files,
        private ProcessRunner $processes,
        private string $orbitHome,
    ) {}

    public function converge(Node $gateway, BootstrapGatewayData $data): void
    {
        $prefixLength = $this->prefixLength($data->wireguardSubnet);
        $privateKey = $this->key('private');
        $publicKey = $this->key('public');
        $configuration = new VpnConfiguration(
            server: $gateway,
            subnet: $data->wireguardSubnet,
            prefixLength: $prefixLength,
            port: $data->wireguardPort,
            endpoint: $data->wireguardEndpoint,
            dnsServer: $data->dnsServer,
            dnsThroughWireGuard: true,
            domain: $data->domain,
            serverAddress: "{$data->wireguardAddress}/{$prefixLength}",
            peerAddress: "{$data->wireguardAddress}/{$prefixLength}",
            serverPrivateKey: $privateKey,
            serverPublicKey: $publicKey,
        );
        $generatedPath = rtrim(string: $this->orbitHome, characters: '/').'/generated/wireguard/orbit.conf';
        $this->files->put(
            $generatedPath,
            $this->renderer->render(
                $configuration,
                Node::query()->whereNotNull('wireguard_public_key')->get(),
            ),
        );

        try {
            $this->run(
                step: 'wireguard-server-install',
                errorCode: 'vpn.server_config_install_failed',
                arguments: [
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
                    $generatedPath,
                    self::CANDIDATE_CONFIG,
                ],
            );
            $this->run(
                step: 'wireguard-server-validate',
                errorCode: 'vpn.server_config_invalid',
                arguments: ['sudo', 'wg-quick', 'strip', self::CANDIDATE_CONFIG],
            );
            $this->run(
                step: 'wireguard-server-install',
                errorCode: 'vpn.server_config_install_failed',
                arguments: ['sudo', 'mv', '-f', '--', self::CANDIDATE_CONFIG, self::LIVE_CONFIG],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanupCandidate();

            throw $exception;
        }

        $this->run(
            step: 'wireguard-server-enable',
            errorCode: 'vpn.server_start_failed',
            arguments: ['sudo', 'systemctl', 'enable', 'wg-quick@orbit'],
        );
        $this->run(
            step: 'wireguard-server-restart',
            errorCode: 'vpn.server_start_failed',
            arguments: ['sudo', 'systemctl', 'restart', 'wg-quick@orbit'],
        );
    }

    private function prefixLength(string $subnet): int
    {
        [$network, $prefix] = array_pad(
            array: explode(separator: '/', string: $subnet, limit: 2),
            length: 2,
            value: null,
        );
        $prefixLength = filter_var($prefix, FILTER_VALIDATE_INT);

        if (
            ! is_string($network)
            || ! is_int($prefixLength)
            || $prefixLength < 8
            || $prefixLength > 30
            || ip2long($network) === false
        ) {
            throw new NodeProvisioningException(
                step: 'wireguard-configuration',
                errorCode: 'vpn.configuration_invalid',
                message: "WireGuard subnet [{$subnet}] is invalid.",
            );
        }

        return $prefixLength;
    }

    private function key(string $name): string
    {
        $path = rtrim(string: $this->orbitHome, characters: '/')."/wireguard/{$name}.key";
        $key = file_get_contents($path);

        if (! is_string($key) || trim($key) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-configuration',
                errorCode: 'vpn.configuration_invalid',
                message: "WireGuard key [{$path}] is missing.",
            );
        }

        return trim($key);
    }

    private function cleanupCandidate(): void
    {
        $this->processes->run(new ProcessInvocation([
            'sudo',
            'rm',
            '-f',
            '--',
            self::CANDIDATE_CONFIG,
        ]));
    }

    /** @param non-empty-list<string> $arguments */
    private function run(string $step, string $errorCode, array $arguments): CommandResult
    {
        $result = $this->processes->run(new ProcessInvocation($arguments, timeout: 60.0));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: 'Could not converge the gateway WireGuard service.',
                result: $result,
            );
        }

        return $result;
    }
}
