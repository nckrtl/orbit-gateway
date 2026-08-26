<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Infrastructure\MacOs\MacOsAppDevCertificateManager;
use App\Infrastructure\MacOs\MacOsFilesystemLayout;
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
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

it('generates the Ed25519 key on Darwin and publishes the signer exact leaf without exposing the private key', function (): void {
    [$instance, $workspace] = macos_certificate_models();
    $request = "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n";
    $ssh = new MacOsCertificateTestSsh([
        new CommandResult(0, $request, '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, $request, '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ]);
    $signer = new MacOsCertificateTestSigner;
    $manager = new MacOsAppDevCertificateManager(
        paths: new AppDevHostPaths,
        layout: new MacOsFilesystemLayout,
        connections: macos_certificate_connections(),
        ssh: $ssh,
        guard: new MacOsSteadyStateCommandGuard,
        signer: $signer,
    );

    $manager->convergeInstance($instance);
    $manager->convergeWorkspace($workspace);

    $surfaces = implode("\n", array_map(
        static fn (RemoteCommand $command): string => implode(' ', $command->arguments)."\n".($command->input ?? ''),
        $ssh->commands,
    ));
    expect($ssh->commands)
        ->toHaveCount(4)
        ->and($ssh->commands[0]->arguments)
        ->toContain('/opt/homebrew/opt/openssl@3/bin/openssl', 'acme.mini.orbit')
        ->and($ssh->commands[0]->input)
        ->toContain(
            'genpkey -algorithm ED25519',
            'req -new -key "$candidate/key.pem"',
            'x509 -in "$target/cert.pem" -noout -checkend 2592000',
            'ED25519 Public-Key:',
            'X509v3 Basic Constraints: critical CA:FALSE',
            'X509v3 Key Usage: critical Digital Signature',
            'X509v3 Extended Key Usage: TLS Web Server Authentication',
            'X509v3 Subject Alternative Name: DNS:$hostname',
            'cat "$candidate/request.pem"',
        )
        ->not->toContain('sudo')->and($signer->requests)->toBe([
            ['acme.mini.orbit',             $request],
            ['feature-one.acme.mini.orbit', $request],
        ])->and($ssh->commands[1]->input)->toContain(
            base64_encode(MacOsCertificateTestSigner::LEAF),
            base64_encode(MacOsCertificateTestSigner::ROOT),
            'x509 -in "$candidate/cert.pem" -noout -checkhost "$hostname"',
            'pkey -in "$candidate/key.pem" -pubout',
            'mv -h -f -- "$temporary_link" "$root/current"',
        )->and($surfaces)
        ->not->toContain('PRIVATE KEY')
        ->not->toContain('sudo');
});

it('renews a current certificate whose lifetime is 398 days', function (): void {
    [$instance] = macos_certificate_models();
    $ssh = new MacOsCertificateTestSsh([
        new CommandResult(
            0,
            "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n",
            '',
            1,
            false,
        ),
        new CommandResult(0, '', '', 1, false),
    ]);
    $manager = new MacOsAppDevCertificateManager(
        new AppDevHostPaths,
        new MacOsFilesystemLayout,
        macos_certificate_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new MacOsCertificateTestSigner,
    );

    $manager->convergeInstance($instance);

    expect($ssh->commands[0]->input)
        ->toContain('[ "$validity_seconds" -le 34300800 ]')
        ->not->toContain('34387200');
});

it('fails before certificate mutation when a managed ancestor is a symlink', function (): void {
    [$instance] = macos_certificate_models();
    $ssh = new MacOsCertificateTestSsh([new CommandResult(1, '', 'ancestor symlink', 1, false)]);
    $signer = new MacOsCertificateTestSigner;
    $manager = new MacOsAppDevCertificateManager(
        new AppDevHostPaths,
        new MacOsFilesystemLayout,
        macos_certificate_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        $signer,
    );

    expect(fn () => $manager->convergeInstance($instance))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    $script = $ssh->commands[0]->input ?? '';
    expect($ssh->commands)
        ->toHaveCount(1)
        ->and($signer->requests)
        ->toBeEmpty()
        ->and($script)
        ->toContain(
            'for managed_directory in "$orbit_root" "$certificates_root" "$root" "$versions_root"',
            'if [ -L "$managed_directory" ]; then exit 1; fi',
            'mkdir -- "$managed_directory"',
        )
        ->and(mb_strpos(haystack: $script, needle: 'if [ -L "$managed_directory" ]'))
        ->toBeLessThan(mb_strpos(haystack: $script, needle: 'mkdir -- "$managed_directory"'));
});

it('revalidates certificate ancestors before writing the signed leaf', function (): void {
    [$instance] = macos_certificate_models();
    $request = "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n";
    $ssh = new MacOsCertificateTestSsh([
        new CommandResult(0, $request, '', 1, false),
        new CommandResult(1, '', 'ancestor changed', 1, false),
    ]);
    $manager = new MacOsAppDevCertificateManager(
        new AppDevHostPaths,
        new MacOsFilesystemLayout,
        macos_certificate_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new MacOsCertificateTestSigner,
    );

    expect(fn () => $manager->convergeInstance($instance))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    $script = $ssh->commands[1]->input ?? '';
    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($script)
        ->toContain(
            'for managed_directory in "$orbit_root" "$certificates_root" "$root" "$versions_root" "$candidate"',
            'if [ -L "$managed_directory" ]; then exit 1; fi',
            'test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"',
        )
        ->and(mb_strpos(haystack: $script, needle: 'test "$(cd "$managed_directory" && pwd -P)"'))
        ->toBeLessThan(mb_strpos(haystack: $script, needle: 'base64 --decode > "$candidate/cert.pem"'));
});

it('fails closed on regular or directory certificate publication drift', function (): void {
    [$instance] = macos_certificate_models();
    $request = "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n";
    $ssh = new MacOsCertificateTestSsh([
        new CommandResult(0, $request, '', 1, false),
        new CommandResult(1, '', 'publication drift', 1, false),
    ]);
    $manager = new MacOsAppDevCertificateManager(
        new AppDevHostPaths,
        new MacOsFilesystemLayout,
        macos_certificate_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new MacOsCertificateTestSigner,
    );

    expect(fn () => $manager->convergeInstance($instance))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    expect($ssh->commands[0]->input)
        ->toContain(
            'if [ -e "$current" ] || [ -L "$current" ]; then',
            'test -L "$current"',
            'if [ -e "$candidate" ] || [ -L "$candidate" ]; then exit 1; fi',
        )
        ->and($ssh->commands[1]->input)
        ->toContain(
            'test ! -e "$published"; test ! -L "$published"',
            'test ! -e "$temporary_link"; test ! -L "$temporary_link"',
        );
});

it('validates every certificate removal ancestor before recursive deletion', function (): void {
    [$instance] = macos_certificate_models();
    $ssh = new MacOsCertificateTestSsh([new CommandResult(1, '', 'ancestor symlink', 1, false)]);
    $manager = new MacOsAppDevCertificateManager(
        new AppDevHostPaths,
        new MacOsFilesystemLayout,
        macos_certificate_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new MacOsCertificateTestSigner,
    );

    expect(fn () => $manager->removeInstance($instance))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    $script = $ssh->commands[0]->input ?? '';
    expect($script)
        ->toContain(
            'test -d "$home"',
            'for managed_directory in "$orbit_root" "$certificates_root" "$root"',
            'test ! -L "$managed_directory"',
            'test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"',
        )
        ->and(mb_strpos(haystack: $script, needle: 'test ! -L "$managed_directory"'))
        ->toBeLessThan(mb_strpos(haystack: $script, needle: 'find -P "$root" -depth -delete'));
});

/** @return array{Instance, Workspace} */
function macos_certificate_models(): array
{
    $node = new Node([
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.9',
    ]);
    $node->id = 9;
    $node->setRelation('roles', new \Illuminate\Database\Eloquent\Collection([
        new \App\Models\NodeRole([
            'role' => \App\Domain\Nodes\RoleName::AppDev,
            'status' => \App\Domain\Shared\LifecycleStatus::Active,
        ]),
    ]));
    $app = new OrbitApp(['slug' => 'acme', 'repository_url' => 'git@github.com:acme/site.git']);
    $instance = new Instance([
        'name' => 'dev',
        'node_id' => 9,
        'checkout_path' => '/Users/nckrtl/apps/acme',
        'hostname' => 'acme.mini.orbit',
    ]);
    $instance->id = 3;
    $instance->setRelation('node', $node);
    $instance->setRelation('app', $app);
    $workspace = new Workspace([
        'name' => 'feature-one',
        'checkout_path' => '/Users/nckrtl/.orbit/worktrees/acme/feature-one',
        'hostname' => 'feature-one.acme.mini.orbit',
    ]);
    $workspace->id = 4;
    $workspace->setRelation('instance', $instance);

    return [$instance, $workspace];
}

function macos_certificate_connections(): MacOsSshConnectionFactory
{
    return new MacOsSshConnectionFactory(
        new class implements HostKeyScanner {
            public function scan(string $host, int $port): HostKey
            {
                return new HostKey('ssh-ed25519', 'AAAAC3', 'SHA256:test');
            }
        },
        new class implements KnownHostsStore {
            public function path(): string
            {
                return '/tmp/orbit-known-hosts';
            }

            public function put(string $host, int $port, HostKey $key): void {}
        },
        new class implements SshKeyProvider {
            public function privateKeyPath(): string
            {
                return '/tmp/orbit-key';
            }

            public function publicKey(): string
            {
                return 'ssh-ed25519 AAAA gateway';
            }
        },
    );
}

final class MacOsCertificateTestSigner implements LeafCertificateSigner
{
    public const string LEAF = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
    public const string ROOT = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n";

    /** @var list<array{string, string}> */
    public array $requests = [];

    public function sign(string $hostname, string $certificateRequest): string
    {
        $this->requests[] = [$hostname, $certificateRequest];

        return self::LEAF;
    }

    public function rootCertificate(): string
    {
        return self::ROOT;
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fake keeps certificate surfaces observable. */
final class MacOsCertificateTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @param list<CommandResult> $results */
    public function __construct(
        private array $results,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;

        return array_shift($this->results) ?? new CommandResult(0, '', '', 1, false);
    }
}
