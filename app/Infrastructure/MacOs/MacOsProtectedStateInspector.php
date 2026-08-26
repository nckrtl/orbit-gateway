<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\MacOs\MacOsProtectedCheck;
use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;

final readonly class MacOsProtectedStateInspector
{
    public function __construct(
        private SshExecutor $ssh,
    ) {}

    /** @mago-expect lint:halstead The inspector compares one fixed protected-state projection in read order. */
    public function inspect(Node $node, SshConnection $connection): void
    {
        $address = $node->wireguard_address;
        $tld = $node->tld;

        if (! is_string($address) || ! is_string($tld)) {
            throw new MacOsProtectedDriftException(MacOsProtectedCheck::PfAnchor);
        }

        $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/launchctl', 'print', 'system/com.openssh.sshd']),
            MacOsProtectedCheck::RemoteLogin,
        );
        $anchor = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/cat', '/etc/pf.anchors/com.orbit.app-dev']),
            MacOsProtectedCheck::PfAnchor,
        );
        $expectedAnchor = implode(PHP_EOL, [
            '# Orbit app-dev managed PF anchor',
            "rdr pass inet proto tcp from any to {$address} port 80 -> {$address} port 8080",
            "rdr pass inet proto tcp from any to {$address} port 443 -> {$address} port 8443",
        ]);
        $this->requireExact($anchor->stdout, $expectedAnchor, MacOsProtectedCheck::PfAnchor);
        $this->requireRootFile($connection, '/etc/pf.anchors/com.orbit.app-dev', MacOsProtectedCheck::PfAnchor);

        $pfConfig = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/cat', '/etc/pf.conf']),
            MacOsProtectedCheck::PfAnchor,
        );
        $pfBlock = implode(PHP_EOL, [
            '# BEGIN ORBIT APP-DEV',
            'rdr-anchor "com.orbit.app-dev"',
            'load anchor "com.orbit.app-dev" from "/etc/pf.anchors/com.orbit.app-dev"',
            '# END ORBIT APP-DEV',
        ]);

        if (substr_count($pfConfig->stdout, $pfBlock) !== 1) {
            throw new MacOsProtectedDriftException(MacOsProtectedCheck::PfAnchor);
        }
        $this->requireRootFile($connection, '/etc/pf.conf', MacOsProtectedCheck::PfAnchor);

        $activePf = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/sbin/pfctl', '-a', 'com.orbit.app-dev', '-sr']),
            MacOsProtectedCheck::PfAnchor,
        );

        if (
            substr_count($activePf->stdout, $address) < 2
            || ! str_contains($activePf->stdout, '8080')
            || ! str_contains($activePf->stdout, '8443')
        ) {
            throw new MacOsProtectedDriftException(MacOsProtectedCheck::PfAnchor);
        }

        $resolver = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/cat', "/etc/resolver/{$tld}"]),
            MacOsProtectedCheck::Resolver,
        );
        $this->requireExact($resolver->stdout, 'nameserver 127.0.0.1', MacOsProtectedCheck::Resolver);
        $this->requireRootFile($connection, "/etc/resolver/{$tld}", MacOsProtectedCheck::Resolver);

        $dnsmasq = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/cat', '/Library/Application Support/Orbit/app-dev/dnsmasq.conf']),
            MacOsProtectedCheck::Dnsmasq,
        );
        $expectedDnsmasq = implode(PHP_EOL, [
            'port=53',
            'listen-address=127.0.0.1',
            'bind-interfaces',
            'no-resolv',
            'no-hosts',
            "address=/{$tld}/{$address}",
        ]);
        $this->requireExact($dnsmasq->stdout, $expectedDnsmasq, MacOsProtectedCheck::Dnsmasq);
        $this->requireRootFile(
            $connection,
            '/Library/Application Support/Orbit/app-dev/dnsmasq.conf',
            MacOsProtectedCheck::Dnsmasq,
        );

        $dnsmasqPlist = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/cat', '/Library/LaunchDaemons/com.orbit.dnsmasq.plist']),
            MacOsProtectedCheck::Dnsmasq,
        );
        $brewPrefix = $node->architecture === 'x86_64' ? '/usr/local' : '/opt/homebrew';

        foreach ([
            '<string>com.orbit.dnsmasq</string>',
            "<string>{$brewPrefix}/opt/dnsmasq/sbin/dnsmasq</string>",
            '<string>--keep-in-foreground</string>',
            '<string>--conf-file=/Library/Application Support/Orbit/app-dev/dnsmasq.conf</string>',
        ] as $requiredPlistValue) {
            if (! str_contains($dnsmasqPlist->stdout, $requiredPlistValue)) {
                throw new MacOsProtectedDriftException(MacOsProtectedCheck::Dnsmasq);
            }
        }
        $this->requireRootFile(
            $connection,
            '/Library/LaunchDaemons/com.orbit.dnsmasq.plist',
            MacOsProtectedCheck::Dnsmasq,
        );

        $this->requireSuccess(
            $connection,
            new RemoteCommand(['/bin/launchctl', 'print', 'system/com.orbit.dnsmasq']),
            MacOsProtectedCheck::Dnsmasq,
        );
        $listeners = $this->requireSuccess(
            $connection,
            new RemoteCommand([
                '/usr/sbin/lsof',
                '-nP',
                '-a',
                '-c',
                'dnsmasq',
                '-iTCP:53',
                '-iUDP:53',
                '-Fn',
            ]),
            MacOsProtectedCheck::Dnsmasq,
        );
        $listenerLines = preg_split('/\R/', trim($listeners->stdout));
        $listenerLines = is_array($listenerLines)
            ? array_values(array_filter($listenerLines, static fn (string $line): bool => str_starts_with($line, 'n')))
            : [];

        if ($listenerLines === []) {
            throw new MacOsProtectedDriftException(MacOsProtectedCheck::Dnsmasq);
        }

        foreach ($listenerLines as $listener) {
            if ($listener !== 'n127.0.0.1:53') {
                throw new MacOsProtectedDriftException(MacOsProtectedCheck::Dnsmasq);
            }
        }
    }

    private function requireSuccess(
        SshConnection $connection,
        RemoteCommand $command,
        MacOsProtectedCheck $check,
    ): CommandResult {
        $result = $this->ssh->execute($connection, $command);

        if (! $result->succeeded()) {
            throw new MacOsProtectedDriftException($check);
        }

        return $result;
    }

    private function requireExact(string $actual, string $expected, MacOsProtectedCheck $check): void
    {
        if (rtrim(string: $actual, characters: "\r\n") !== $expected) {
            throw new MacOsProtectedDriftException($check);
        }
    }

    private function requireRootFile(
        SshConnection $connection,
        string $path,
        MacOsProtectedCheck $check,
    ): void {
        $stat = $this->requireSuccess(
            $connection,
            new RemoteCommand(['/usr/bin/stat', '-f', '%Su:%Sg:%Lp', $path]),
            $check,
        );
        $this->requireExact($stat->stdout, 'root:wheel:644', $check);
    }
}
