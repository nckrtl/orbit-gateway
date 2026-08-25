<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\AppDev\AppDevCaddyConfigRenderer;
use App\Infrastructure\AppDev\AppDevCaddyPublisher;
use App\Infrastructure\AppDev\AppDevPhpFpmConfigRenderer;
use App\Infrastructure\AppDev\AppDevSiteRepository;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppDev\DnsmasqPrivateDnsManager;
use App\Infrastructure\AppDev\RemoteAppDevCaddyManager;
use App\Infrastructure\AppDev\RemoteAppDevCertificateManager;
use App\Infrastructure\AppDev\RemoteAppDevPhpFpmManager;
use App\Infrastructure\AppDev\RemoteAppDevSourceManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;
use Tests\Support\AppDevCaddyPublishHarness;
use Tests\Support\AppDevCaddyPublishScenario;
use Tests\Support\AppDevFakeProcessRunner;
use Tests\Support\AppDevFakeSshExecutor;

it('renders isolated pools and private Caddy listeners for every active scope', function (): void {
    [$node, $instance, $workspace] = app_dev_runtime_models();
    $sites = new AppDevSiteRepository()->forNode($node);
    $fpm = new AppDevPhpFpmConfigRenderer()->render($sites);
    $caddy = new AppDevCaddyConfigRenderer()->render($sites);
    $adapted = new NativeProcessRunner()->run(new ProcessInvocation(
        arguments: ['caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile'],
        input: $caddy,
    ));

    expect($sites)
        ->toHaveCount(2)
        ->and($fpm)
        ->toContain(
            '[orbit-instance-1]',
            'listen = /run/php/orbit-instance-1.sock',
            '[orbit-workspace-1]',
            'listen = /run/php/orbit-workspace-1.sock',
            'listen.group = caddy',
        )
        ->and($caddy)
        ->toContain(
            "https://{$instance->hostname}",
            "https://{$workspace->hostname}",
            'bind 10.44.0.3',
            'php_fastcgi unix//run/php/orbit-instance-1.sock',
            'tls /etc/caddy/orbit-certificates/instance-1/current/cert.pem',
        )
        ->not->toContain('0.0.0.0', ':80')->and($adapted->succeeded())->toBeTrue()->and($adapted->stdout)->toContain(
            '10.44.0.3:443',
        )
        ->not->toContain('0.0.0.0:443', '127.0.0.1:443');
});

it('uses only generated instance paths and registered Git worktrees for source removal', function (): void {
    [, $instance, $workspace] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();

    $manager->convergeInstance($instance);
    $manager->convergeWorkspace($workspace);
    $manager->removeWorkspace($workspace);
    $manager->removeInstance($instance);

    expect($ssh->commands)
        ->toHaveCount(4)
        ->and($ssh->commands[0]->arguments)
        ->toContain('git@github.com:acme/site.git', '/home/orbit/apps/acme')
        ->and($ssh->commands[0]->input)
        ->toContain(
            'git -C "$checkout" remote get-url origin',
            'realpath -e "$existing_parent"',
            'test ! -L "$current"',
        )
        ->and($ssh->commands[1]->input)
        ->toContain(
            'git -C "$checkout" symbolic-ref --quiet --short HEAD',
            'realpath -e "$existing_parent"',
            'test ! -L "$current"',
        )
        ->and($ssh->commands[2]->input)
        ->toContain(
            'worktree list --porcelain',
            'worktree remove --force -- "$checkout"',
        )
        ->and($ssh->commands[3]->input)
        ->toContain(
            'case "$(realpath -e "$parent")" in',
            'test ! -L "$checkout"',
            'git -C "$checkout" rev-parse --show-toplevel',
            'rm -rf -- "$checkout"',
        );
});

it('rejects a corrupted instance checkout path before SSH or recursive removal', function (): void {
    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $instance->checkout_path = '/etc';

    expect(fn () => $manager->removeInstance($instance))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('instance.checkout_path_unsafe');
        })
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('installs selected PHP versions and validates a complete staged FPM configuration before publication', function (): void {
    [$node] = app_dev_runtime_models(instancePhp: '8.4');
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.5\n", '', 1, false),
    ]);
    $manager = new RemoteAppDevPhpFpmManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevPhpFpmConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    $manager->converge($node);

    $publishCalls = collect($ssh->commands)
        ->filter(static fn (RemoteCommand $command): bool => str_contains($command->input ?? '', 'php-fpm.conf'))
        ->values();

    expect($ssh->commands)
        ->toHaveCount(4)
        ->and($ssh->commands[1]->input)
        ->toContain('apt-get install', '"php$version-fpm"')
        ->and($publishCalls)
        ->toHaveCount(2)
        ->and($publishCalls->first()?->input)
        ->toContain(
            'cp -- "$pool" "$temporary_directory/pool.d/"',
            'sudo "php-fpm$version" -y "$temporary_directory/php-fpm.conf" -t',
            'sudo mv -fT -- "$candidate" "$managed_configuration"',
        );
});

it('rejects an unsupported PHP version before target discovery or installation', function (): void {
    [$node] = app_dev_runtime_models(instancePhp: '9.9');
    $ssh = new AppDevFakeSshExecutor;
    $manager = new RemoteAppDevPhpFpmManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevPhpFpmConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    expect(fn () => $manager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.php_version_unsupported');
        })
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('keeps leaf private keys on the target while publishing a gateway-signed certificate', function (): void {
    [, $instance] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(0, 'CSR FROM TARGET', '', 1, false),
    ]);
    $signer = new class implements LeafCertificateSigner {
        /** @var list<array{hostname: string, csr: string}> */
        public array $calls = [];

        public function sign(string $hostname, string $certificateRequest): string
        {
            $this->calls[] = ['hostname' => $hostname, 'csr' => $certificateRequest];

            return "LEAF CERTIFICATE\n";
        }

        public function rootCertificate(): string
        {
            return "ROOT CERTIFICATE\n";
        }
    };
    $manager = new RemoteAppDevCertificateManager(app_dev_ssh($ssh), $signer);

    $manager->convergeInstance($instance);

    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($ssh->commands[0]->input)
        ->toContain(
            'openssl genpkey -algorithm ED25519',
            'cat "$candidate/request.pem"',
            'openssl verify -CAfile "$current/root.pem" "$current/cert.pem"',
            'sha256sum "$current/root.pem"',
        )
        ->and($ssh->commands[0]->arguments)
        ->toContain(hash(algo: 'sha256', data: "ROOT CERTIFICATE\n"))
        ->and($signer->calls)
        ->toBe([['hostname' => 'acme.app-dev.orbit', 'csr' => 'CSR FROM TARGET']])
        ->and($ssh->commands[1]->input)
        ->toBe("LEAF CERTIFICATE\nROOT CERTIFICATE\n")
        ->and($ssh->commands[1]->arguments[2])
        ->toContain(
            'head -c "$certificate_length"',
            'openssl verify -CAfile',
            'sudo install -o root -g caddy -m 0640 -- "$published/key.pem"',
        )
        ->not->toContain('PRIVATE KEY');
});

it('publishes private Caddy and DNS configurations through complete preserved validation aggregates', function (): void {
    [$node] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $caddyRenderer = new AppDevCaddyConfigRenderer;
    $caddy = new RemoteAppDevCaddyManager(
        sites: new AppDevSiteRepository,
        renderer: $caddyRenderer,
        ssh: app_dev_ssh($ssh),
    );
    $processes = new AppDevFakeProcessRunner;
    $dns = new DnsmasqPrivateDnsManager(new AppDevSiteRepository, $processes);

    $caddy->converge($node);
    $dns->converge();

    $expectedCaddy = $caddyRenderer->render(new AppDevSiteRepository()->forNode($node));

    expect($ssh->commands[0]->input)
        ->toContain(
            base64_encode($expectedCaddy),
            'source_main=$(readlink -f "$live_caddyfile")',
            'previous_fragments=$(dirname "$source_main")/fragments',
            'cp --preserve=mode,ownership -- "$fragment" "$candidate/fragments/"',
            'app-dev.caddy',
            "printf 'import fragments/*.caddy\n'",
            'caddy validate --config "$candidate/Caddyfile"',
            'mv -fT -- "$candidate_link" "$live_caddyfile"',
        )
        ->and($processes->invocations)
        ->toHaveCount(1)
        ->and($processes->invocations[0]->input)
        ->toContain(
            base64_encode(
                "# Managed by Orbit.\nhost-record=acme.app-dev.orbit,10.44.0.3\nhost-record=app-dev.orbit,10.44.0.3\nhost-record=feature.acme.app-dev.orbit,10.44.0.3\n",
            ),
            'cp -a -- /etc/dnsmasq.d/. "$validation/fragments/"',
            'sed "s#/etc/dnsmasq.d#$validation/fragments#g" /etc/dnsmasq.conf',
            'dnsmasq --test --conf-file="$validation/dnsmasq.conf"',
            'mv -fT -- "$candidate" "$managed"',
        );
});

it('retires only the exact package-default caddyfile while preserving modified config and orbit fragments', function (): void {
    $harness = new AppDevCaddyPublishHarness;

    try {
        $defaultResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::packageDefault("package default\n", "package default\n"),
        );

        expect($defaultResult->exitCode)
            ->toBe(0)
            ->and($defaultResult->publishedFragments)
            ->toHaveKey('app-dev.caddy')
            ->not->toHaveKey('unmanaged.caddy');

        $orbitResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::orbitAggregate("import fragments/*.caddy\n", [
                'custom.caddy' => "custom handler\n",
                'app-dev.caddy' => "stale app-dev\n",
            ]),
        );

        expect($orbitResult->exitCode)
            ->toBe(0)
            ->and($orbitResult->publishedFragments)
            ->toHaveKey('app-dev.caddy')
            ->toHaveKey('custom.caddy')
            ->not
            ->toHaveKey('unmanaged.caddy')
            ->and($orbitResult->publishedFragments['custom.caddy'])
            ->toBe("custom handler\n")
            ->and($orbitResult->publishedFragments['app-dev.caddy'])
            ->toBe("# Managed by Orbit.\n");

        $modifiedResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::modifiedConfig("modified config\n", "package default\n"),
        );

        expect($modifiedResult->exitCode)
            ->toBe(0)
            ->and($modifiedResult->publishedFragments)
            ->toHaveKey('unmanaged.caddy')
            ->and($modifiedResult->publishedFragments['unmanaged.caddy'])
            ->toBe("modified config\n");
    } finally {
        $harness->cleanup();
    }
});

it('leaves the live caddy aggregate unchanged when staged validation fails during zero-site publication', function (): void {
    $harness = new AppDevCaddyPublishHarness;

    try {
        $result = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::modifiedConfigWithValidationFailure(
                "modified config\n",
                "package default\n",
            ),
        );

        expect($result->exitCode)
            ->not
            ->toBe(0)
            ->and($result->liveMainAfter)
            ->toBe("modified config\n")
            ->and($result->publishedFragments)
            ->toBeEmpty();
    } finally {
        $harness->cleanup();
    }
});

it('keeps the live Caddy aggregate untouched when candidate validation fails', function (): void {
    [$node] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(1, '', 'invalid candidate', 1, false),
    ]);
    $manager = new RemoteAppDevCaddyManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevCaddyConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    expect(fn () => $manager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.caddy_config_failed');
        });

    $script = $ssh->commands[0]->input ?? '';
    $validation = mb_strpos(haystack: $script, needle: 'caddy validate --config "$candidate/Caddyfile"');
    $liveSwitch = mb_strpos(
        haystack: $script,
        needle: 'mv -fT -- "$candidate_link" "$live_caddyfile"',
    );

    expect($validation)
        ->toBeInt()
        ->and($liveSwitch)
        ->toBeInt()
        ->and($validation)
        ->toBeLessThan($liveSwitch)
        ->and($script)
        ->toContain('sudo rm -rf -- "$candidate" "$candidate_link"');
});

it('keeps the live DNS fragment untouched when effective validation fails', function (): void {
    app_dev_runtime_models();
    $processes = new AppDevFakeProcessRunner;
    $processes->fail = true;
    $manager = new DnsmasqPrivateDnsManager(new AppDevSiteRepository, $processes);

    expect($manager->converge(...))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.dns_config_failed');
        });

    $script = $processes->invocations[0]->input ?? '';
    $validation = mb_strpos(
        haystack: $script,
        needle: 'dnsmasq --test --conf-file="$validation/dnsmasq.conf"',
    );
    $liveSwitch = mb_strpos(
        haystack: $script,
        needle: 'mv -fT -- "$candidate" "$managed"',
    );

    expect($validation)
        ->toBeInt()
        ->and($liveSwitch)
        ->toBeInt()
        ->and($validation)
        ->toBeLessThan($liveSwitch)
        ->and($script)
        ->toContain('trap \'rm -rf -- "$validation"; rm -f -- "$candidate"\' EXIT');
});

/** @return array{Node, Instance, Workspace} */
function app_dev_runtime_models(string $instancePhp = '8.5'): array
{
    $node = Node::query()->create([
        'name' => 'app-dev',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.3',
        'ssh_user' => 'orbit',
    ]);
    $app = OrbitApp::query()->create([
        'name' => 'Acme',
        'slug' => 'acme',
        'repository_url' => 'git@github.com:acme/site.git',
    ]);
    $instance = Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'dev',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/acme',
        'document_root' => 'public',
        'php_version' => $instancePhp,
        'hostname' => 'acme.app-dev.orbit',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);
    $workspace = Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'feature',
        'branch' => 'feature',
        'checkout_path' => '/home/orbit/.orbit/worktrees/acme/feature',
        'hostname' => 'feature.acme.app-dev.orbit',
        'status' => LifecycleStatus::Active,
    ]);

    return [$node, $instance, $workspace];
}

/** @return array{RemoteAppDevSourceManager, AppDevFakeSshExecutor} */
function source_manager(): array
{
    $ssh = new AppDevFakeSshExecutor;

    return [new RemoteAppDevSourceManager(app_dev_ssh($ssh)), $ssh];
}

function zero_site_publisher(AppDevCaddyPublishHarness $harness): AppDevCaddyPublisher
{
    return new AppDevCaddyPublisher(
        versionsDirectory: $harness->etcCaddyPath('orbit-versions'),
        liveCaddyfilePath: $harness->etcCaddyPath('Caddyfile'),
        caddyServiceName: 'caddy',
    );
}

function app_dev_ssh(AppDevFakeSshExecutor $ssh): AppDevSshExecutor
{
    $keys = new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/home/orbit/.orbit/ssh/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 AAAA';
        }
    };
    $knownHosts = new class implements KnownHostsStore {
        public function path(): string
        {
            return '/home/orbit/.orbit/ssh/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };

    return new AppDevSshExecutor($ssh, $keys, $knownHosts);
}
