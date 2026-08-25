<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;

final readonly class DnsmasqPrivateDnsManager implements PrivateDnsManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private ProcessRunner $processes,
    ) {}

    public function converge(): void
    {
        $nodeRecords = Node::query()
            ->where('status', 'active')
            ->whereNotNull('wireguard_address')
            ->get()
            ->map(static fn (Node $node): string => sprintf(
                'host-record=%s.%s,%s',
                $node->name,
                (string) config('orbit.app_dev_domain'),
                $node->wireguard_address,
            ))
            ->toBase();
        $siteRecords = $this->sites
            ->all()
            ->map(static fn (AppDevSite $site): string => "host-record={$site->hostname},{$site->nodeAddress}");
        $configuration = $nodeRecords
            ->merge($siteRecords)
            ->unique()
            ->sort()
            ->implode(PHP_EOL);
        $configuration = '# Managed by Orbit.'.PHP_EOL.$configuration.PHP_EOL;
        $encoded = base64_encode($configuration);
        $result = $this->processes->run(new ProcessInvocation(
            arguments: ['sudo', 'bash', '-seu'],
            timeout: 60.0,
            input: <<<BASH
                managed=/etc/dnsmasq.d/orbit-records.conf
                candidate=/etc/dnsmasq.d/.orbit-records.\$\$.candidate
                validation=\$(mktemp -d)
                trap 'rm -rf -- "\$validation"; rm -f -- "\$candidate"' EXIT
                install -d -m 0755 -- "\$validation/fragments"
                cp -a -- /etc/dnsmasq.d/. "\$validation/fragments/"
                printf '%s' '{$encoded}' | base64 --decode > "\$validation/fragments/orbit-records.conf"
                sed "s#/etc/dnsmasq.d#\$validation/fragments#g" /etc/dnsmasq.conf > "\$validation/dnsmasq.conf"
                dnsmasq --test --conf-file="\$validation/dnsmasq.conf"
                install -o root -g root -m 0644 -- "\$validation/fragments/orbit-records.conf" "\$candidate"
                mv -fT -- "\$candidate" "\$managed"
                systemctl reload-or-restart dnsmasq
                BASH,
        ));

        if (! $result->succeeded()) {
            throw new RuntimeConvergenceException(
                step: 'private-dns',
                errorCode: 'app-dev.dns_config_failed',
                message: 'Could not converge Orbit private DNS records.',
                result: $result,
            );
        }
    }
}
