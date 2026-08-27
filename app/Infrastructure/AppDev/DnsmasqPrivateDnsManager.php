<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;
use Illuminate\Database\Eloquent\Builder;
use RuntimeException;

final readonly class DnsmasqPrivateDnsManager implements PrivateDnsManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private ProcessRunner $processes,
    ) {}

    public function converge(?Node $pendingNode = null): void
    {
        /** @mago-expect analysis:mixed-assignment Laravel configuration is an untyped boundary. */
        $configuredHome = config('orbit.home');
        $orbitHome = is_string($configuredHome) ? rtrim(string: $configuredHome, characters: '/') : '';

        if ($orbitHome === '') {
            throw new RuntimeException('The Orbit home is not configured.');
        }

        if (
            ! is_dir($orbitHome)
            && ! mkdir(directory: $orbitHome, permissions: 0o700, recursive: true)
            && ! is_dir($orbitHome)
        ) {
            throw new RuntimeException("Could not create Orbit home [{$orbitHome}].");
        }

        $lockPath = $orbitHome.'/.dnsmasq-projections.lock';
        $lock = fopen(filename: $lockPath, mode: 'c+');

        if ($lock === false) {
            throw new RuntimeException("Could not open DNS projection lock [{$lockPath}].");
        }

        try {
            if (! flock($lock, LOCK_EX)) {
                throw new RuntimeException("Could not acquire DNS projection lock [{$lockPath}].");
            }

            $this->publish($pendingNode);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function publish(?Node $pendingNode): void
    {
        $nodeRecords = Node::query()
            ->where(static function (Builder $query) use ($pendingNode): void {
                $query->where('status', 'active');

                if (
                    $pendingNode instanceof Node
                    && $pendingNode->exists
                    && $pendingNode->status === LifecycleStatus::Provisioning
                ) {
                    $query->orWhere('id', $pendingNode->id);
                }
            })
            ->whereHas('roles', static function (Builder $query): void {
                $query->where('role', RoleName::AppDev->value)
                    ->whereIn('status', [LifecycleStatus::Provisioning, LifecycleStatus::Active]);
            })
            ->whereNotNull('wireguard_address')
            ->whereNotNull('tld')
            ->get()
            ->flatMap(static fn (Node $node): array => [
                "address=/.{$node->tld}/{$node->wireguard_address}",
                "local=/{$node->tld}/",
            ])
            ->toBase();
        $siteRecords = $this->sites
            ->all()
            ->map(static fn (AppDevSite $site): string => "host-record={$site->hostname},{$site->nodeAddress}");
        $gatewayRecord = Node::query()
            ->where('status', LifecycleStatus::Active)
            ->whereNotNull('wireguard_address')
            ->whereHas('roles', static function (Builder $query): void {
                $query->where('role', RoleName::Gateway->value)
                    ->where('status', LifecycleStatus::Active);
            })
            ->first();
        $records = $nodeRecords->merge($siteRecords);

        if ($gatewayRecord instanceof Node) {
            $records->push("host-record=gateway.orbit,{$gatewayRecord->wireguard_address}");
        }

        $configuration = $records
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
                backup=\$(mktemp /etc/dnsmasq.d/.orbit-records.backup.XXXXXX)
                had_managed=0
                trap 'rm -rf -- "\$validation"; rm -f -- "\$candidate" "\$backup"' EXIT
                exec 9>/run/lock/orbit-dnsmasq.lock
                flock -w 30 9
                if [ -f "\$managed" ]; then
                    cp --preserve=mode,ownership -- "\$managed" "\$backup"
                    had_managed=1
                fi
                install -d -m 0755 -- "\$validation/fragments"
                cp -a -- /etc/dnsmasq.d/. "\$validation/fragments/"
                printf '%s' '{$encoded}' | base64 --decode > "\$validation/fragments/orbit-records.conf"
                sed "s#/etc/dnsmasq.d#\$validation/fragments#g" /etc/dnsmasq.conf > "\$validation/dnsmasq.conf"
                dnsmasq --test --conf-file="\$validation/dnsmasq.conf"
                if [ -f "\$managed" ] && cmp -s -- "\$validation/fragments/orbit-records.conf" "\$managed"; then
                    if systemctl is-active --quiet dnsmasq; then
                        exit 0
                    fi
                    systemctl restart dnsmasq
                    exit 0
                fi
                install -o root -g root -m 0644 -- "\$validation/fragments/orbit-records.conf" "\$candidate"
                mv -fT -- "\$candidate" "\$managed"
                if ! systemctl restart dnsmasq; then
                    if [ "\$had_managed" = 1 ]; then
                        install -o root -g root -m 0644 -- "\$backup" "\$managed"
                    else
                        rm -f -- "\$managed"
                    fi
                    systemctl restart dnsmasq || true
                    exit 1
                fi
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
