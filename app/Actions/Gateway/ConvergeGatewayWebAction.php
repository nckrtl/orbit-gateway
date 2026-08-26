<?php

declare(strict_types=1);

namespace App\Actions\Gateway;

use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\VpnSettings;
use App\Models\Node;

final readonly class ConvergeGatewayWebAction
{
    public function __construct(
        private VpnSettings $vpnSettings,
        private GatewayWebConverger $web,
    ) {}

    public function execute(): void
    {
        $domain = $this->vpnSettings->configuredDomain();

        if ($domain === null || $domain === '') {
            throw $this->invalidState('The configured Gateway domain is missing.');
        }

        $gateways = Node::query()
            ->whereHas('roles', static fn ($query) => $query->where('role', RoleName::Gateway->value))
            ->get();

        if ($gateways->count() !== 1) {
            throw $this->invalidState('Gateway state must contain exactly one Gateway-role node.');
        }

        $gateway = $gateways->sole();

        if (! is_string($gateway->wireguard_address) || $gateway->wireguard_address === '') {
            throw $this->invalidState('The Gateway WireGuard address is missing.');
        }

        $this->web->converge("{$gateway->name}.{$domain}", $gateway->wireguard_address);
    }

    private function invalidState(string $message): ResourceOperationException
    {
        return new ResourceOperationException(
            errorCode: 'gateway.web_state_invalid',
            message: $message,
            status: 409,
        );
    }
}
