<?php

declare(strict_types=1);

namespace App\Domain\WireGuard;

use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;

final readonly class VpnSettings
{
    private const string SUBNET = 'vpn.subnet';

    private const string PORT = 'vpn.port';

    private const string ENDPOINT = 'vpn.endpoint';

    private const string DNS_SERVER = 'vpn.dns_server';

    private const string DOMAIN = 'vpn.domain';

    private const string PRIVATE_INTERFACE = 'vpn.private_interface';

    public function __construct(
        private SettingRepository $settings,
    ) {}

    /** @mago-expect lint:excessive-parameter-list The complete VPN configuration has six named scalar settings. */
    public function configure(
        string $subnet,
        int $port = 51_820,
        ?string $endpoint = null,
        ?string $dnsServer = null,
        string $domain = 'orbit',
        ?string $privateInterface = null,
    ): void {
        $scope = $this->scope();
        $this->settings->put($scope, self::SUBNET, $subnet);
        $this->settings->put($scope, self::PORT, (string) $port);
        $this->settings->put($scope, self::ENDPOINT, $endpoint);
        $this->settings->put($scope, self::DNS_SERVER, $dnsServer);
        $this->settings->put($scope, self::DOMAIN, $domain);
        $this->settings->put($scope, self::PRIVATE_INTERFACE, $privateInterface);
    }

    public function subnet(): string
    {
        return $this->settings->get($this->scope(), self::SUBNET) ?? '10.44.0.0/24';
    }

    public function port(): string
    {
        return $this->settings->get($this->scope(), self::PORT) ?? '51820';
    }

    public function endpoint(): ?string
    {
        return $this->settings->get($this->scope(), self::ENDPOINT);
    }

    public function dnsServer(): ?string
    {
        return $this->settings->get($this->scope(), self::DNS_SERVER);
    }

    public function domain(): string
    {
        return $this->settings->get($this->scope(), self::DOMAIN) ?? 'orbit';
    }

    public function configuredDomain(): ?string
    {
        return $this->settings->get($this->scope(), self::DOMAIN);
    }

    public function privateInterface(): ?string
    {
        return $this->settings->get($this->scope(), self::PRIVATE_INTERFACE);
    }

    private function scope(): SettingScope
    {
        return new SettingScope(SettingScopeType::Gateway);
    }
}
