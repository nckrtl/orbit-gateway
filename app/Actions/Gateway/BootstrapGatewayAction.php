<?php

declare(strict_types=1);

namespace App\Actions\Gateway;

use App\Actions\Nodes\AssignRoleAction;
use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;

/** @mago-expect lint:cyclomatic-complexity */
final readonly class BootstrapGatewayAction
{
    public function __construct(
        private AssignRoleAction $assignRole,
        private SettingRepository $settings,
        private ProcessRunner $processes,
        private ProtectedFileWriter $files,
        private string $orbitHome,
    ) {}

    public function execute(BootstrapGatewayData $data): Node
    {
        $this->ensureDirectories();
        $this->ensureSshKeys();
        $wireGuardPublicKey = $this->ensureWireGuardKeys();
        $this->ensureCertificateAuthority();

        $node = Node::query()->updateOrCreate(
            ['name' => $data->name],
            [
                'status' => LifecycleStatus::Active,
                'platform' => 'linux',
                'architecture' => php_uname('m'),
                'public_ssh_host' => $data->publicHost,
                'public_ssh_port' => 22,
                'ssh_user' => 'orbit',
                'wireguard_address' => $data->wireguardAddress,
                'wireguard_public_key' => $wireGuardPublicKey,
                'failed_step' => null,
                'error_code' => null,
            ],
        );

        foreach ([RoleName::Gateway, RoleName::Vpn] as $role) {
            $this->assignRole->execute($node, $role)->update(['status' => LifecycleStatus::Active]);
        }

        $scope = new SettingScope(SettingScopeType::Gateway);
        $this->settings->put($scope, 'vpn.subnet', $data->wireguardSubnet);
        $this->settings->put($scope, 'vpn.port', (string) $data->wireguardPort);
        $this->settings->put($scope, 'vpn.endpoint', $data->wireguardEndpoint);
        $this->settings->put($scope, 'vpn.dns_server', $data->dnsServer);
        $this->settings->put($scope, 'vpn.domain', $data->domain);
        $this->settings->put($scope, 'vpn.private_interface', $data->privateInterface);

        return $node->load('roles');
    }

    private function ensureDirectories(): void
    {
        foreach (['', 'ca', 'generated', 'logs', 'ssh', 'wireguard'] as $directory) {
            $path = rtrim(string: $this->orbitHome.'/'.$directory, characters: '/');

            if (! is_dir($path) && ! mkdir(directory: $path, permissions: 0o700, recursive: true) && ! is_dir($path)) {
                throw new NodeProvisioningException(
                    step: 'gateway-directories',
                    errorCode: 'gateway.directory_failed',
                    message: "Could not create gateway directory [{$path}].",
                );
            }

            chmod(filename: $path, permissions: 0o700);
        }
    }

    private function ensureSshKeys(): void
    {
        $privateKey = $this->orbitHome.'/ssh/id_ed25519';

        if (! is_file($privateKey) || ! is_file($privateKey.'.pub')) {
            $this->run('gateway-ssh-key', 'gateway.ssh_key_failed', [
                'ssh-keygen',
                '-q',
                '-t',
                'ed25519',
                '-N',
                '',
                '-C',
                'orbit-gateway',
                '-f',
                $privateKey,
            ]);
        }

        chmod(filename: $privateKey, permissions: 0o600);
        chmod(filename: $privateKey.'.pub', permissions: 0o644);
    }

    private function ensureWireGuardKeys(): string
    {
        $privatePath = $this->orbitHome.'/wireguard/private.key';
        $publicPath = $this->orbitHome.'/wireguard/public.key';

        if (! is_file($privatePath)) {
            $privateKey = trim($this->run(
                'wireguard-private-key',
                'vpn.key_generation_failed',
                ['wg', 'genkey'],
            )->stdout);
            $this->files->put($privatePath, $privateKey.PHP_EOL);
        }

        $privateKey = file_get_contents($privatePath);

        if (! is_string($privateKey) || trim($privateKey) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-private-key',
                errorCode: 'vpn.key_generation_failed',
                message: 'The gateway WireGuard private key is invalid.',
            );
        }

        if (! is_file($publicPath)) {
            $publicKey = trim($this->run(
                'wireguard-public-key',
                'vpn.key_generation_failed',
                ['wg', 'pubkey'],
                input: $privateKey,
            )->stdout);
            $this->files->put($publicPath, $publicKey.PHP_EOL, 0o644);
        }

        $publicKey = file_get_contents($publicPath);

        if (! is_string($publicKey) || trim($publicKey) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-public-key',
                errorCode: 'vpn.key_generation_failed',
                message: 'The gateway WireGuard public key is invalid.',
            );
        }

        return trim($publicKey);
    }

    private function ensureCertificateAuthority(): void
    {
        $privateKey = $this->orbitHome.'/ca/root.key';
        $certificate = $this->orbitHome.'/ca/root.pem';

        if (! is_file($privateKey)) {
            $this->run('ca-private-key', 'ca.key_generation_failed', [
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                $privateKey,
            ]);
        }

        if (! is_file($certificate)) {
            $this->run('ca-root-certificate', 'ca.certificate_generation_failed', [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $privateKey,
                '-out',
                $certificate,
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
            ]);
        }

        chmod(filename: $privateKey, permissions: 0o600);
        chmod(filename: $certificate, permissions: 0o644);
    }

    /** @param non-empty-list<string> $arguments */
    private function run(
        string $step,
        string $errorCode,
        array $arguments,
        ?string $input = null,
    ): \App\Infrastructure\Processes\CommandResult {
        $result = $this->processes->run(new ProcessInvocation(
            arguments: $arguments,
            timeout: 60.0,
            input: $input,
        ));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: "Gateway bootstrap step [{$step}] failed.",
                result: $result,
            );
        }

        return $result;
    }
}
