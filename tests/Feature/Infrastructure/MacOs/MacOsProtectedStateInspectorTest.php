<?php

declare(strict_types=1);

use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Infrastructure\MacOs\MacOsProtectedStateInspector;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;

it('reads and proves every protected setup projection without sudo or mutation', function (): void {
    $ssh = new MacOsInspectorFakeSshExecutor;
    $inspector = new MacOsProtectedStateInspector($ssh);

    $inspector->inspect(macos_inspector_node(), macos_inspector_connection());

    expect($ssh->commands)
        ->toHaveCount(14)
        ->and(array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments),
            $ssh->commands,
        ))
        ->each(
            fn ($command) => $command
                ->not->toContain('sudo')
                ->not->toContain('install ')
                ->not->toContain('bootout')
                ->not->toContain('bootstrap'),
        );
});

it('classifies protected drift with only the backed check and null command', function (
    string $failedSurface,
    string $check,
): void {
    $ssh = new MacOsInspectorFakeSshExecutor($failedSurface);
    $inspector = new MacOsProtectedStateInspector($ssh);

    try {
        $inspector->inspect(macos_inspector_node(), macos_inspector_connection());
    } catch (MacOsProtectedDriftException $exception) {
        expect($exception->safeDetails)->toBe([
            'check' => $check,
            'local_command' => null,
        ]);

        return;
    }

    test()->fail('Expected protected drift to require a local action.');
})->with([
    'Remote Login' => ['system/com.openssh.sshd', 'remote-login'],
    'PF anchor bytes' => ['/etc/pf.anchors/com.orbit.app-dev', 'pf-anchor'],
    'PF activation' => ['-a com.orbit.app-dev', 'pf-anchor'],
    'resolver bytes' => ['/etc/resolver/test', 'resolver'],
    'dnsmasq bytes' => ['dnsmasq.conf', 'dnsmasq'],
    'dnsmasq definition' => ['com.orbit.dnsmasq.plist', 'dnsmasq'],
    'dnsmasq loaded state' => ['system/com.orbit.dnsmasq', 'dnsmasq'],
    'dnsmasq listener' => ['-iTCP:53', 'dnsmasq'],
]);

function macos_inspector_node(): Node
{
    return new Node([
        'name' => 'mini',
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'tld' => 'test',
        'public_ssh_host' => '10.44.0.8',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.8',
    ]);
}

function macos_inspector_connection(): SshConnection
{
    return new SshConnection(
        host: '10.44.0.8',
        user: 'nckrtl',
        port: 22,
        identityFile: '/gateway/id_ed25519',
        knownHostsFile: '/gateway/known_hosts',
    );
}

/** @mago-expect lint:file-name The test-local fake keeps protected read surfaces visible. */
final class MacOsInspectorFakeSshExecutor implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    public function __construct(
        private readonly ?string $failedSurface = null,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;
        $surface = implode(' ', $command->arguments);

        if ($this->failedSurface !== null && str_contains($surface, $this->failedSurface)) {
            return new CommandResult(
                exitCode: 1,
                stdout: '',
                stderr: 'unsafe diagnostic sentinel',
                durationMs: 1,
                truncated: false,
            );
        }

        $stdout = match (true) {
            str_starts_with($surface, '/usr/bin/stat ') => "root:wheel:644\n",
            str_contains($surface, '/usr/sbin/lsof') => "p101\nf10\nn127.0.0.1:53\n",
            str_contains($surface, '/etc/pf.anchors/com.orbit.app-dev') => <<<'TEXT'
                # Orbit app-dev managed PF anchor
                rdr pass inet proto tcp from any to 10.44.0.8 port 80 -> 10.44.0.8 port 8080
                rdr pass inet proto tcp from any to 10.44.0.8 port 443 -> 10.44.0.8 port 8443
                TEXT,
            str_contains($surface, '/etc/pf.conf') => <<<'TEXT'
                set skip on lo0
                # BEGIN ORBIT APP-DEV
                rdr-anchor "com.orbit.app-dev"
                load anchor "com.orbit.app-dev" from "/etc/pf.anchors/com.orbit.app-dev"
                # END ORBIT APP-DEV
                TEXT,
            str_contains($surface, '-a com.orbit.app-dev') => '10.44.0.8 80 8080 10.44.0.8 443 8443',
            str_contains($surface, '/etc/resolver/test') => "nameserver 127.0.0.1\n",
            str_contains($surface, 'dnsmasq.conf') => <<<'TEXT'
                port=53
                listen-address=127.0.0.1
                bind-interfaces
                no-resolv
                no-hosts
                address=/test/10.44.0.8
                TEXT,
            str_contains($surface, 'com.orbit.dnsmasq.plist') => <<<'TEXT'
                <string>com.orbit.dnsmasq</string>
                <string>/opt/homebrew/opt/dnsmasq/sbin/dnsmasq</string>
                <string>--keep-in-foreground</string>
                <string>--conf-file=/Library/Application Support/Orbit/app-dev/dnsmasq.conf</string>
                TEXT,
            default => '',
        };

        return new CommandResult(
            exitCode: 0,
            stdout: $stdout,
            stderr: '',
            durationMs: 1,
            truncated: false,
        );
    }
}
