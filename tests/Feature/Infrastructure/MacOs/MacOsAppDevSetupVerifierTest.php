<?php

declare(strict_types=1);

use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\MacOs\MacOsAppDevSetupVerifier;
use App\Infrastructure\MacOs\MacOsProtectedStateInspector;
use App\Infrastructure\MacOs\MacOsSshConnectionFactory;
use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

it('verifies identity, protected state, restricted key, toolchain, and user services without sudo', function (): void {
    $ssh = new MacOsVerifierFakeSshExecutor;
    $verifier = macos_test_verifier($ssh);
    $node = macos_verifier_node();

    $verifier->verify($node);

    expect($ssh->commands)
        ->not
        ->toBeEmpty()
        ->and($ssh->connections)
        ->each(
            fn ($connection) => $connection
                ->host->toBe('10.44.0.8')
                ->user->toBe('nckrtl')
                ->port->toBe(22),
        )
        ->and(array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments),
            $ssh->commands,
        ))
        ->each(fn ($surface) => $surface->not->toContain('sudo'))
        ->and($node->ssh_host_fingerprint)
        ->toBe('SHA256:mini');
});

it('keeps the first SSH transport failure distinct from verification checks', function (): void {
    $verifier = macos_test_verifier(new MacOsVerifierFakeSshExecutor('/usr/bin/id -un'));

    try {
        $verifier->verify(macos_verifier_node());
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('node.unreachable')
            ->and($exception->status)
            ->toBe(502)
            ->and($exception->safeDetails)
            ->toBeEmpty();

        return;
    }

    test()->fail('Expected SSH transport failure to report node.unreachable.');
});

it('returns the exact stable verification check for a live mismatch', function (
    string $failedSurface,
    string $check,
): void {
    $verifier = macos_test_verifier(new MacOsVerifierFakeSshExecutor($failedSurface));

    try {
        $verifier->verify(macos_verifier_node());
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('macos.verification_failed')
            ->and($exception->status)
            ->toBe(502)
            ->and($exception->safeDetails)
            ->toBe(['check' => $check]);

        return;
    }

    test()->fail('Expected the live mismatch to fail verification.');
})->with([
    'identity' => ['=/usr/bin/id -u', 'identity'],
    'architecture' => ['/usr/bin/uname -m', 'architecture'],
    'restricted key' => ['authorized_keys', 'restricted-key'],
    'Homebrew prefix' => ['brew --prefix', 'homebrew'],
    'toolchain' => ['composer --version', 'toolchain'],
    'Caddy readiness' => ['=/usr/sbin/lsof -nP -a -c caddy -iTCP -sTCP:LISTEN -Fn', 'caddy'],
    'PHP-FPM readiness' => ['health-8.5.sock', 'php-fpm'],
]);

it('returns the launchd runtime error when the GUI domain is unavailable', function (): void {
    $verifier = macos_test_verifier(new MacOsVerifierFakeSshExecutor('gui/501'));

    try {
        $verifier->verify(macos_verifier_node());
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('macos.user_session_unavailable')
            ->and($exception->status)
            ->toBe(409)
            ->and($exception->safeDetails)
            ->toBe(['runtime' => 'launchd']);

        return;
    }

    test()->fail('Expected the unavailable GUI domain to return the launchd runtime error.');
});

it('rejects every Caddy loopback, admin, wildcard, or unapproved listener', function (string $listener): void {
    $ssh = new MacOsVerifierFakeSshExecutor(caddyListeners: implode("\n", [
        'p120',
        'f10',
        'n10.44.0.8:8080',
        'f11',
        'n10.44.0.8:8443',
        'f12',
        $listener,
    ]));

    try {
        macos_test_verifier($ssh)->verify(macos_verifier_node());
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('macos.verification_failed')
            ->and($exception->safeDetails)
            ->toBe(['check' => 'caddy']);

        return;
    }

    test()->fail('Expected the unapproved Caddy listener to fail verification.');
})->with([
    'TCP 2019 on WireGuard' => ['n10.44.0.8:2019'],
    'IPv4 loopback' => ['n127.0.0.1:8080'],
    'IPv6 loopback' => ['n[::1]:2019'],
    'localhost admin' => ['nlocalhost:2019'],
    'wildcard admin' => ['n*:2019'],
    'unapproved WireGuard port' => ['n10.44.0.8:9000'],
]);

function macos_test_verifier(MacOsVerifierFakeSshExecutor $ssh): MacOsAppDevSetupVerifier
{
    $keys = new MacOsVerifierFakeSshKeyProvider;
    $connections = new MacOsSshConnectionFactory(
        new MacOsVerifierFakeHostKeyScanner,
        new MacOsVerifierFakeKnownHostsStore,
        $keys,
    );

    return new MacOsAppDevSetupVerifier(
        connections: $connections,
        ssh: $ssh,
        sshKeys: $keys,
        guard: new MacOsSteadyStateCommandGuard,
        protectedState: new MacOsProtectedStateInspector($ssh),
        gatewayAddressResolver: static fn (): string => '10.44.0.1',
    );
}

function macos_verifier_node(): Node
{
    return new Node([
        'name' => 'mini',
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'tld' => 'test',
        'public_ssh_host' => '192.0.2.8',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.8',
    ]);
}

final readonly class MacOsVerifierFakeHostKeyScanner implements HostKeyScanner
{
    public function scan(string $host, int $port): HostKey
    {
        return new HostKey('ssh-ed25519', 'AAAA-mini', 'SHA256:mini');
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fakes keep live verification deterministic. */
final class MacOsVerifierFakeKnownHostsStore implements KnownHostsStore
{
    public function path(): string
    {
        return '/gateway/known_hosts';
    }

    public function put(string $host, int $port, HostKey $key): void {}
}

/** @mago-expect lint:single-class-per-file Test-local SSH fakes keep live verification deterministic. */
final readonly class MacOsVerifierFakeSshKeyProvider implements SshKeyProvider
{
    public function privateKeyPath(): string
    {
        return '/gateway/id_ed25519';
    }

    public function publicKey(): string
    {
        return 'ssh-ed25519 AAAAC3NzaGatewayKey orbit-gateway';
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fakes keep live verification deterministic. */
final class MacOsVerifierFakeSshExecutor implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @var list<SshConnection> */
    public array $connections = [];

    public function __construct(
        private readonly ?string $failedSurface = null,
        private readonly ?string $caddyListeners = null,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->connections[] = $connection;
        $this->commands[] = $command;
        $surface = implode(' ', $command->arguments);

        $failsExactly =
            $this->failedSurface !== null
            && str_starts_with($this->failedSurface, '=')
            && $surface === substr(string: $this->failedSurface, offset: 1);
        $failsBySurface =
            $this->failedSurface !== null
            && ! str_starts_with($this->failedSurface, '=')
            && str_contains($surface, $this->failedSurface);

        if ($failsExactly || $failsBySurface) {
            return new CommandResult(
                exitCode: 1,
                stdout: '',
                stderr: 'private failure sentinel',
                durationMs: 1,
                truncated: false,
            );
        }

        $stdout = match (true) {
            $surface === '/usr/bin/id -un' => "nckrtl\n",
            $surface === '/usr/bin/id -u' => "501\n",
            $surface === '/usr/bin/uname -m' => "arm64\n",
            str_contains($surface, '%Su:%Lp /Users/nckrtl/.ssh/authorized_keys') => "nckrtl:600\n",
            str_contains($surface, '%Su:%Lp /Users/nckrtl/.ssh') => "nckrtl:700\n",
            str_starts_with($surface, '/usr/bin/stat ') => "root:wheel:644\n",
            str_contains($surface, '-c dnsmasq') => "p101\nf10\nn127.0.0.1:53\n",
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
            str_contains($surface, 'authorized_keys') => <<<'TEXT'
                ssh-ed25519 AAAA-unrelated personal
                from="10.44.0.1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc ssh-ed25519 AAAAC3NzaGatewayKey orbit-gateway
                TEXT,
            str_contains($surface, 'brew --prefix') => "/opt/homebrew\n",
            str_contains($surface, 'Caddyfile') => "{\n    admin off\n}\n",
            str_contains($surface, '/usr/sbin/lsof') => $this->caddyListeners
                ?? "p120\nf10\nn10.44.0.8:8080\nf11\nn10.44.0.8:8443\n",
            str_contains($surface, 'list -public-key-algorithms') => "ED25519\n",
            str_contains($surface, '/usr/bin/find')
                => "/Users/nckrtl/Library/LaunchAgents/com.orbit.php-fpm.8.5.plist\n",
            default => "ok\n",
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
