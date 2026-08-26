<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\RoleName;
use Illuminate\Console\Command;

final class ProvisionNodeCommand extends Command
{
    #[\Override]
    protected $signature = 'orbit:node-provision
        {name : Node name}
        {host : Public SSH host}
        {--ssh-port=22 : Public SSH port}
        {--ssh-user=root : Initial SSH user}
        {--platform=linux : Node platform (linux or darwin)}
        {--architecture= : Node machine architecture}
        {--tld= : Unique development TLD for app-dev}
        {--role=* : Initial role assignment}
        {--wireguard-address= : Stable WireGuard address}
        {--wireguard-endpoint= : Per-node WireGuard endpoint override}
        {--dns-server= : Per-node DNS server override}
        {--host-key-fingerprint= : Expected first-contact SSH SHA256 fingerprint}';

    #[\Override]
    protected $description = 'Provision the first node directly from the gateway.';

    public function handle(ProvisionNodeAction $action): int
    {
        $name = $this->stringArgument('name');
        $host = $this->stringArgument('host');
        $sshPort = $this->option('ssh-port');
        $sshUser = $this->stringOption('ssh-user');
        $roles = $this->roles();

        if ($name === null || $host === null || ! is_numeric($sshPort) || $sshUser === null || $roles === null) {
            $this->error('Node provisioning arguments are invalid.');

            return self::FAILURE;
        }

        $node = $action->execute(new ProvisionNodeData(
            name: $name,
            publicSshHost: $host,
            roles: $roles,
            publicSshPort: (int) $sshPort,
            sshUser: $sshUser,
            wireguardAddress: $this->stringOption('wireguard-address'),
            wireguardEndpointOverride: $this->stringOption('wireguard-endpoint'),
            dnsServerOverride: $this->stringOption('dns-server'),
            expectedSshHostFingerprint: $this->stringOption('host-key-fingerprint'),
            platform: $this->stringOption('platform') ?? 'linux',
            architecture: $this->stringOption('architecture'),
            tld: $this->stringOption('tld'),
        ));

        $this->info("Node [{$node->name}] is {$node->status->value}.");

        return self::SUCCESS;
    }

    private function stringArgument(string $name): ?string
    {
        $value = $this->argument($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @mago-expect analysis:mixed-assignment Console option values are an untyped boundary.
     *
     * @return list<RoleName>|null
     */
    private function roles(): ?array
    {
        $values = $this->option('role');

        if (! is_array($values)) {
            return null;
        }

        $roles = [];

        foreach ($values as $value) {
            if (! is_string($value) || RoleName::tryFrom($value) === null) {
                return null;
            }

            $roles[] = RoleName::from($value);
        }

        return $roles;
    }
}
