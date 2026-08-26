<?php

declare(strict_types=1);

use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\MacOs\MacOsSshConnectionFactory;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\SshHostKeyScanException;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

it('pins the first private host key and builds the stored-user WireGuard connection', function (): void {
    $hostKey = new HostKey('ssh-ed25519', 'AAAA-first', 'SHA256:first');
    $scanner = new MacOsFactoryFakeHostKeyScanner($hostKey);
    $knownHosts = new MacOsFactoryFakeKnownHostsStore;
    $factory = new MacOsSshConnectionFactory($scanner, $knownHosts, new MacOsFactoryFakeSshKeyProvider);
    $node = macos_factory_node();

    $connection = $factory->make($node);

    expect($scanner->scans)
        ->toBe([['10.44.0.8', 22]])
        ->and($knownHosts->writes)
        ->toBe([['10.44.0.8', 22, $hostKey]])
        ->and($connection->host)
        ->toBe('10.44.0.8')
        ->and($connection->user)
        ->toBe('nckrtl')
        ->and($connection->port)
        ->toBe(22)
        ->and($connection->identityFile)
        ->toBe('/gateway/id_ed25519')
        ->and($connection->knownHostsFile)
        ->toBe('/gateway/known_hosts')
        ->and($node->ssh_host_key_type)
        ->toBe('ssh-ed25519')
        ->and($node->ssh_host_key)
        ->toBe('AAAA-first')
        ->and($node->ssh_host_fingerprint)
        ->toBe('SHA256:first');
});

it('rejects a changed private host key without replacing the pin', function (): void {
    $scanner = new MacOsFactoryFakeHostKeyScanner(
        new HostKey('ssh-ed25519', 'AAAA-changed', 'SHA256:changed'),
    );
    $knownHosts = new MacOsFactoryFakeKnownHostsStore;
    $factory = new MacOsSshConnectionFactory($scanner, $knownHosts, new MacOsFactoryFakeSshKeyProvider);
    $node = macos_factory_node();
    $node->forceFill([
        'ssh_host_key_type' => 'ssh-ed25519',
        'ssh_host_key' => 'AAAA-first',
        'ssh_host_fingerprint' => 'SHA256:first',
    ]);

    try {
        $factory->make($node);
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('macos.verification_failed')
            ->and($exception->status)
            ->toBe(502)
            ->and($exception->safeDetails)
            ->toBe(['check' => 'ssh-host-key'])
            ->and($knownHosts->writes)
            ->toBeEmpty()
            ->and($node->ssh_host_fingerprint)
            ->toBe('SHA256:first');

        return;
    }

    test()->fail('Expected a changed SSH host key to fail verification.');
});

it('keeps transport failures distinct from named verification checks', function (): void {
    $scanner = new MacOsFactoryFakeHostKeyScanner(
        new SshHostKeyScanException('unreachable'),
    );
    $factory = new MacOsSshConnectionFactory(
        $scanner,
        new MacOsFactoryFakeKnownHostsStore,
        new MacOsFactoryFakeSshKeyProvider,
    );

    try {
        $factory->make(macos_factory_node());
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('node.unreachable')
            ->and($exception->status)
            ->toBe(502)
            ->and($exception->safeDetails)
            ->toBeEmpty();

        return;
    }

    test()->fail('Expected an SSH scan failure to report node.unreachable.');
});

function macos_factory_node(): Node
{
    return new Node([
        'name' => 'mini',
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'public_ssh_host' => '192.0.2.8',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.8',
    ]);
}

final class MacOsFactoryFakeHostKeyScanner implements HostKeyScanner
{
    /** @var list<array{string, int}> */
    public array $scans = [];

    public function __construct(
        private HostKey|SshHostKeyScanException $result,
    ) {}

    public function scan(string $host, int $port): HostKey
    {
        $this->scans[] = [$host, $port];

        if ($this->result instanceof SshHostKeyScanException) {
            throw $this->result;
        }

        return $this->result;
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fakes keep pinning interactions visible. */
final class MacOsFactoryFakeKnownHostsStore implements KnownHostsStore
{
    /** @var list<array{string, int, HostKey}> */
    public array $writes = [];

    public function path(): string
    {
        return '/gateway/known_hosts';
    }

    public function put(string $host, int $port, HostKey $key): void
    {
        $this->writes[] = [$host, $port, $key];
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fakes keep pinning interactions visible. */
final readonly class MacOsFactoryFakeSshKeyProvider implements SshKeyProvider
{
    public function privateKeyPath(): string
    {
        return '/gateway/id_ed25519';
    }

    public function publicKey(): string
    {
        return 'ssh-ed25519 AAAA-gateway';
    }
}
