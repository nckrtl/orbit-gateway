<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\AppProd\AppProdCaddyManager;
use App\Domain\AppProd\AppProdPhpFpmManager;
use App\Domain\AppProd\AppProdSourceManager;
use App\Domain\AppProd\AppProdUserManager;
use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\AppProd\AppProdCaddyConfigRenderer;
use App\Infrastructure\AppProd\AppProdCaddyPublisher;
use App\Infrastructure\AppProd\AppProdPhpFpmConfigRenderer;
use App\Infrastructure\AppProd\AppProdSiteRepository;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Infrastructure\AppProd\NativeAppProdRuntimeConverger;
use App\Infrastructure\AppProd\RemoteAppProdCaddyManager;
use App\Infrastructure\AppProd\RemoteAppProdPhpFpmManager;
use App\Infrastructure\AppProd\RemoteAppProdSourceManager;
use App\Infrastructure\AppProd\RemoteAppProdUserManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Tests\Support\AppDevCaddyPublishHarness;
use Tests\Support\AppDevCaddyPublishScenario;
use Tests\Support\AppDevFakeSshExecutor;
use Tests\Support\FpmPublishHarness;

it('renders isolated production FPM pools and public ACME Caddy sites', function (): void {
    [$node, $instance] = app_prod_runtime_models();
    $sites = new AppProdSiteRepository()->forNode($node);

    $fpm = new AppProdPhpFpmConfigRenderer()->render($sites);
    $caddy = new AppProdCaddyConfigRenderer()->render($sites);

    expect($fpm)
        ->toContain(
            '[orbit-prod-instance-1]',
            'user = orbit-acme',
            'group = orbit-acme',
            'listen = /run/php/orbit-prod-instance-1.sock',
            'listen.owner = orbit-acme',
            'listen.group = caddy',
            'listen.mode = 0660',
            'clear_env = yes',
            'env[HOME] = /var/www/acme',
            'env[USER] = orbit-acme',
            'env[PATH] = /usr/local/bin:/usr/bin:/bin',
            'access.log = /var/log/orbit/php-fpm/instance-1.access.log',
            'slowlog = /var/log/orbit/php-fpm/instance-1.slow.log',
        )
        ->not->toContain('opcache.')->and($caddy)->toContain(
            "https://{$instance->hostname}",
            'root * /var/www/acme/main/public',
            'php_fastcgi unix//run/php/orbit-prod-instance-1.sock',
            'file_server',
        )
        ->not->toContain('tls internal', 'orbit-certificates', 'frankenphp', 'docker', 'swarm', 'h3');
});

it('uses fixed production identity, clone, ownership, and exact removal guards', function (): void {
    [, $instance] = app_prod_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $executor = app_prod_ssh($ssh);
    $users = new RemoteAppProdUserManager($executor);
    $source = new RemoteAppProdSourceManager($executor);

    $users->converge($instance);
    $source->converge($instance);
    $source->remove($instance);
    $users->remove($instance);

    expect($ssh->commands)
        ->toHaveCount(5)
        ->and($ssh->commands[0]->arguments)
        ->toBe(['bash', '-seu', '--', 'orbit-acme', 'acme'])
        ->and($ssh->commands[0]->input)
        ->toContain(
            'useradd --system --user-group --home-dir "$app_root" --shell /usr/sbin/nologin -- "$user"',
            'test "$actual_shell" = /usr/sbin/nologin',
            'test ! -L "$app_root"',
            'install -d -o "$user" -g "$user" -m 0700 -- "$app_root"',
        )
        ->and($ssh->commands[1]->input)
        ->toContain(
            'test "$(sudo -u "$user" -H -- git -C "$checkout" remote get-url origin)" = "$repository"',
            'test "$(sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"',
            'test "$(sudo -u "$user" -H -- stat -c %U "$checkout")" = "$user"',
        )
        ->and($ssh->commands[2]->arguments)
        ->toBe([
            'bash',
            '-seu',
            '--',
            'orbit-acme',
            'acme',
            'main',
            'git@github.com:acme/site.git',
            '/var/www/acme/main',
            'public',
        ])
        ->and($ssh->commands[2]->input)
        ->toContain(
            'sudo -u "$user" -H -- git clone -- "$repository" "$checkout"',
            'sudo -u "$user" -H -- git -C "$checkout" remote get-url origin',
            'sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel',
            'test "$(sudo -u "$user" -H -- stat -c %U "$checkout")" = "$user"',
            'setfacl -P -R -m u:caddy:--- "$checkout_root"',
            'setfacl -P -R -m u:caddy:r-X "$document_root_real"',
        )
        ->and($ssh->commands[3]->arguments)
        ->toBe([
            'sudo',
            'bash',
            '-seu',
            '--',
            'orbit-acme',
            'acme',
            'main',
            'git@github.com:acme/site.git',
            '/var/www/acme/main',
        ])
        ->and($ssh->commands[3]->input)
        ->toContain(
            'test "$checkout" = "/var/www/$slug/$instance"',
            'test "$(sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"',
            'test "$(sudo -u "$user" -H -- git -C "$checkout" remote get-url origin)" = "$repository"',
            'sudo -u "$user" -H -- rm -rf -- "$checkout"',
        )
        ->and($ssh->commands[4]->input)
        ->toContain(
            <<<'BASH'
                if ! getent passwd "$user" >/dev/null; then
                    exit 0
                fi
                BASH,
            'test "$(stat -c %G "$app_root")" = "$user"',
            'test -z "$(find "$app_root" -mindepth 1 -maxdepth 1 -print -quit)"',
            'test -z "$(pgrep -u "$user" || true)"',
            'userdel -- "$user"',
            'rmdir -- "$app_root"',
        )
        ->not->toContain('userdel -r', 'rm -rf "$app_root"');
});

it('runs every isolated source probe as the exact app user across clone retry and removal', function (): void {
    [, $instance] = app_prod_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $source = new RemoteAppProdSourceManager(app_prod_ssh($ssh));

    $source->converge($instance);
    $source->remove($instance);

    $driftProbe = $ssh->commands[0]->input ?? '';
    $converge = $ssh->commands[1]->input ?? '';
    $remove = $ssh->commands[2]->input ?? '';

    expect($driftProbe)
        ->toContain(
            'if ! sudo -u "$user" -H -- test -e "$checkout"; then',
            'sudo -u "$user" -H -- test -d "$checkout"',
            'sudo -u "$user" -H -- test ! -L "$checkout"',
            'sudo -u "$user" -H -- realpath -e "$checkout"',
            'sudo -u "$user" -H -- stat -c %U "$checkout"',
            'sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel',
            'sudo -u "$user" -H -- git -C "$checkout" remote get-url origin',
        );

    $checkoutProbe = mb_strpos(
        haystack: $converge,
        needle: 'if ! sudo -u "$user" -H -- test -e "$checkout"; then',
    );
    $clone = mb_strpos(
        haystack: $converge,
        needle: 'sudo -u "$user" -H -- git clone -- "$repository" "$checkout"',
    );

    expect($checkoutProbe)
        ->toBeInt()
        ->toBeLessThan($clone)
        ->and($converge)
        ->toContain(
            'sudo -u "$user" -H -- test -f "$checkout/.env"',
            'sudo -u "$user" -H -- test ! -L "$checkout/.env"',
            'sudo -u "$user" -H -- realpath -e "$document_root_path"',
            'sudo -u "$user" -H -- find -P "$document_root_real" -type l -print0',
            'sudo -u "$user" -H -- realpath -e "$link"',
            'sudo -u "$user" -H -- test -d "$expected_target"',
            'sudo -u "$user" -H -- find -P "$expected_target" -type l -print -quit',
        )
        ->and($remove)
        ->toContain(
            'if ! sudo -u "$user" -H -- test -e "$checkout"; then',
            'sudo -u "$user" -H -- test -d "$checkout"',
            'sudo -u "$user" -H -- test ! -L "$checkout"',
            'sudo -u "$user" -H -- realpath -e "$checkout"',
            'sudo -u "$user" -H -- stat -c %U "$checkout"',
            'sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel',
            'sudo -u "$user" -H -- git -C "$checkout" remote get-url origin',
            'sudo -u "$user" -H -- rm -rf -- "$checkout"',
        );
});

it('rejects an unsafe stored repository origin before app-prod SSH execution', function (): void {
    [, $instance] = app_prod_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $manager = new RemoteAppProdSourceManager(app_prod_ssh($ssh));
    $sentinel = 'sentinel-app-prod-password';
    $instance
        ->app
        ->forceFill([
            'repository_url' => "ssh://git:{$sentinel}@example.test/acme/site.git",
        ])
        ->save();
    $exception = null;

    try {
        $manager->converge($instance);
    } catch (InvalidArgumentException $caught) {
        $exception = $caught;
    }

    $appOwnedTrace = array_values(array_filter(
        $exception?->getTrace() ?? [],
        static fn (array $frame): bool => (
            is_string($frame['class'] ?? null) && str_starts_with($frame['class'], 'App\\')
        ),
    ));
    $debugOutput = json_encode([
        'message' => $exception?->getMessage(),
        'trace' => $appOwnedTrace,
    ], JSON_THROW_ON_ERROR);

    expect($exception)
        ->toBeInstanceOf(InvalidArgumentException::class)
        ->and($exception?->getMessage())
        ->toBe('The Git repository origin is invalid.')
        ->and($debugOutput)
        ->not
        ->toContain($sentinel)
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('validates aggregate FPM candidates and restores the managed pool after activation failure', function (): void {
    [$node] = app_prod_runtime_models();
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.5\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ]);
    $manager = new RemoteAppProdPhpFpmManager(
        sites: new AppProdSiteRepository,
        renderer: new AppProdPhpFpmConfigRenderer,
        ssh: app_prod_ssh($ssh),
    );

    $manager->converge($node);

    expect($ssh->commands)
        ->toHaveCount(6)
        ->and($ssh->commands[1]->arguments)
        ->toContain('8.5')
        ->and($ssh->commands[1]->input)
        ->toContain('/usr/sbin/php-fpm$version')
        ->and($ssh->commands[2]->input)
        ->toContain('apt-cache policy -- "$package"')
        ->and($ssh->commands[3]->input)
        ->toContain(
            'apt-get -o DPkg::Lock::Timeout=300 install',
            'php$version-cli',
            'php$version-fpm',
        )
        ->and($ssh->commands[5]->input)
        ->toContain(
            'exec 9>"$lock_directory/orbit-php-fpm-$version.lock"',
            'flock -w 30 9',
            'cp -- "$pool" "$temporary_directory/pool.d/"',
            'php-fpm$version" -y "$temporary_directory/php-fpm.conf" -t',
            'cmp -s -- "$candidate" "$managed_configuration"',
            'cp -a -- "$managed_configuration" "$backup"',
            'if ! sudo systemctl enable "php$version-fpm" || ! sudo systemctl reload-or-restart "php$version-fpm"; then',
            'cp -a -- "$backup" "$rollback"',
            'sudo mv -fT -- "$rollback" "$managed_configuration"',
            'sudo systemctl reload-or-restart "php$version-fpm" || true',
        );

    $script = $ssh->commands[5]->input ?? '';
    $lock = mb_strpos(haystack: $script, needle: 'flock -w 30 9');
    $snapshot = mb_strpos(haystack: $script, needle: 'for pool in "$pool_directory"/*.conf');
    $validation = mb_strpos(
        haystack: $script,
        needle: 'php-fpm$version" -y "$temporary_directory/php-fpm.conf" -t',
    );
    $switch = mb_strpos(
        haystack: $script,
        needle: 'sudo mv -fT -- "$staged" "$managed_configuration"',
    );
    $activation = mb_strpos(haystack: $script, needle: 'if ! sudo systemctl enable');
    $rollback = mb_strpos(
        haystack: $script,
        needle: 'sudo mv -fT -- "$rollback" "$managed_configuration"',
    );

    expect($lock)
        ->toBeInt()
        ->toBeLessThan($snapshot)
        ->and($validation)
        ->toBeInt()
        ->toBeLessThan($switch)
        ->and($switch)
        ->toBeInt()
        ->toBeLessThan($activation)
        ->and($activation)
        ->toBeInt()
        ->toBeLessThan($rollback);
});

it('keeps AppProd package-source and install failures stable', function (): void {
    [$node] = app_prod_runtime_models();
    $sourceFailureSsh = new AppDevFakeSshExecutor([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "8.5\n", '', 1, false),
        new CommandResult(0, "8.5\n", '', 1, false),
        new CommandResult(1, '', 'source unavailable', 1, false),
    ]);
    $sourceFailureManager = new RemoteAppProdPhpFpmManager(
        sites: new AppProdSiteRepository,
        renderer: new AppProdPhpFpmConfigRenderer,
        ssh: app_prod_ssh($sourceFailureSsh),
    );

    expect(fn () => $sourceFailureManager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->step)
                ->toBe('app-prod-php-package-source')
                ->and($exception->errorCode)
                ->toBe('app-prod.php_package_source_unavailable');
        });

    $installFailureSsh = new AppDevFakeSshExecutor([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "8.5\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'install failed', 1, false),
    ]);
    $installFailureManager = new RemoteAppProdPhpFpmManager(
        sites: new AppProdSiteRepository,
        renderer: new AppProdPhpFpmConfigRenderer,
        ssh: app_prod_ssh($installFailureSsh),
    );

    expect(fn () => $installFailureManager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->step)
                ->toBe('app-prod-php-fpm-install')
                ->and($exception->errorCode)
                ->toBe('app-prod.php_install_failed');
        });
});

it('restores the exact AppProd FPM file before the recovery reload when activation fails', function (): void {
    [$node] = app_prod_runtime_models();
    $harness = new FpmPublishHarness;
    $managed = $harness->prepare('8.5', 'orbit-prod-scopes.conf', "previous app-prod pool\n");
    $ssh = new AppDevFakeSshExecutor([new CommandResult(0, "8.5\n", '', 1, false)]);

    try {
        $manager = new RemoteAppProdPhpFpmManager(
            sites: new AppProdSiteRepository,
            renderer: new AppProdPhpFpmConfigRenderer,
            ssh: app_prod_ssh($ssh),
            phpRoot: $harness->phpRoot(),
            lockDirectory: $harness->lockDirectory(),
            logDirectory: $harness->logDirectory(),
        );
        $manager->converge($node);
        $result = $harness->run($ssh->commands[2]);

        expect($result->succeeded())
            ->toBeFalse($result->stderr)
            ->and(file_get_contents($managed))
            ->toBe("previous app-prod pool\n")
            ->and(fileperms($managed) & 0o777)
            ->toBe(0o600)
            ->and($harness->serviceCalls())
            ->toBe(
                [
                    'enable php8.5-fpm',
                    'reload-or-restart php8.5-fpm',
                    'reload-or-restart php8.5-fpm',
                ],
                $result->stderr,
            );
    } finally {
        $harness->cleanup();
    }
});

it('publishes one Orbit-owned Caddy fragment and restores the prior aggregate after reload failure', function (): void {
    [$node] = app_prod_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $manager = new RemoteAppProdCaddyManager(
        sites: new AppProdSiteRepository,
        renderer: new AppProdCaddyConfigRenderer,
        ssh: app_prod_ssh($ssh),
    );

    $manager->converge($node);

    $script = $ssh->commands[0]->input ?? '';

    expect($script)
        ->toContain(
            'app-prod.caddy',
            'unmanaged.caddy',
            'exec 9>"$lock"',
            'flock -w 30 9',
            'caddy validate --config "$candidate/Caddyfile" --adapter caddyfile',
            'cmp -s -- "$candidate/fragments/app-prod.caddy" "$current_fragments/app-prod.caddy"',
            'mv -fT -- "$candidate_link" "$live_caddyfile"',
            'if ! systemctl enable "$caddy_service" || ! systemctl reload-or-restart "$caddy_service"; then',
            'mv -fT -- "$rollback_link" "$live_caddyfile"',
            'cp -a -- "$previous_main" "$rollback_file"',
            'mv -fT -- "$rollback_file" "$live_caddyfile"',
            'systemctl reload-or-restart "$caddy_service" || true',
        )
        ->not
        ->toContain('rm -rf -- "$live_caddyfile"')
        ->and($ssh->commands[0]->arguments)
        ->toContain('/run/lock/orbit-caddy.lock');

    $lock = mb_strpos(haystack: $script, needle: 'flock -w 30 9');
    $snapshot = mb_strpos(haystack: $script, needle: 'source_main=$(readlink -f "$live_caddyfile")');
    $validation = mb_strpos(haystack: $script, needle: 'caddy validate --config "$candidate/Caddyfile"');
    $switch = mb_strpos(haystack: $script, needle: 'mv -fT -- "$candidate_link" "$live_caddyfile"');
    $activation = mb_strpos(haystack: $script, needle: 'if ! systemctl enable');
    $rollback = mb_strpos(haystack: $script, needle: 'mv -fT -- "$rollback_link" "$live_caddyfile"');

    expect($lock)
        ->toBeInt()
        ->toBeLessThan($snapshot)
        ->and($validation)
        ->toBeInt()
        ->toBeLessThan($switch)
        ->and($switch)
        ->toBeInt()
        ->toBeLessThan($activation)
        ->and($activation)
        ->toBeInt()
        ->toBeLessThan($rollback);
});

it('restores the exact Caddy symlink before the recovery reload when activation fails', function (): void {
    $harness = new AppDevCaddyPublishHarness;
    $previousTarget = $harness->etcCaddyPath('orbit-versions/current/Caddyfile');

    try {
        $publisher = new AppProdCaddyPublisher(
            versionsDirectory: $harness->etcCaddyPath('orbit-versions'),
            liveCaddyfilePath: $harness->etcCaddyPath('Caddyfile'),
            caddyServiceName: 'caddy',
            lockPath: $harness->etcCaddyPath('orbit-caddy.lock'),
        );
        $result = $harness->run(
            publisher: $publisher,
            scenario: AppDevCaddyPublishScenario::orbitAggregateWithActivationFailure(
                "import fragments/*.caddy\n",
                [
                    'custom.caddy' => "custom handler\n",
                    'app-prod.caddy' => "stale production\n",
                ],
            ),
        );

        expect($result->exitCode)
            ->not
            ->toBe(0)
            ->and($result->liveMainAfter)
            ->toBe("import fragments/*.caddy\n")
            ->and($result->liveLinkTargetAfter)
            ->toBe($previousTarget)
            ->and($result->publishedFragments)
            ->toBeEmpty()
            ->and($result->serviceCalls)
            ->toBe([
                'enable caddy',
                'reload-or-restart caddy',
                'reload-or-restart caddy',
            ]);
    } finally {
        $harness->cleanup();
    }
});

it('converges and removes production runtime components in recovery-safe order', function (): void {
    [, $instance] = app_prod_runtime_models();
    $calls = [];
    $users = new class($calls) implements AppProdUserManager {
        /** @param list<string> $calls */
        public function __construct(
            public array &$calls,
        ) {}

        public function converge(Instance $instance): void
        {
            $this->calls[] = 'user:converge';
        }

        public function remove(Instance $instance): void
        {
            $this->calls[] = 'user:remove';
        }
    };
    $source = new class($calls) implements AppProdSourceManager {
        /** @param list<string> $calls */
        public function __construct(
            public array &$calls,
        ) {}

        public function converge(Instance $instance): void
        {
            $this->calls[] = 'source:converge';
        }

        public function remove(Instance $instance): void
        {
            $this->calls[] = 'source:remove';
        }
    };
    $fpm = new class($calls) implements AppProdPhpFpmManager {
        /** @param list<string> $calls */
        public function __construct(
            public array &$calls,
        ) {}

        public function converge(Node $node): void
        {
            $this->calls[] = 'fpm';
        }
    };
    $caddy = new class($calls) implements AppProdCaddyManager {
        /** @param list<string> $calls */
        public function __construct(
            public array &$calls,
        ) {}

        public function converge(Node $node): void
        {
            $this->calls[] = 'caddy';
        }
    };
    $runtime = new NativeAppProdRuntimeConverger($users, $source, $fpm, $caddy);

    $runtime->convergeInstance($instance);
    $runtime->removeInstance($instance);

    expect($calls)->toBe([
        'user:converge',
        'source:converge',
        'fpm',
        'caddy',
        'caddy',
        'fpm',
        'source:remove',
        'user:remove',
    ]);
});

/** @return array{Node, Instance} */
function app_prod_runtime_models(): array
{
    $node = Node::query()->create([
        'name' => 'app-prod',
        'platform' => 'linux',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.20',
        'wireguard_address' => '10.44.0.5',
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
        'name' => 'main',
        'environment' => 'production',
        'checkout_path' => '/var/www/acme/main',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'orbit.nckrtl.com',
        'certificate_mode' => CertificateMode::Acme,
        'status' => LifecycleStatus::Active,
    ]);

    return [$node, $instance];
}

function app_prod_ssh(AppDevFakeSshExecutor $ssh): AppProdSshExecutor
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

    return new AppProdSshExecutor($ssh, $keys, $knownHosts);
}
