<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Infrastructure\Nodes\RemotePhpPackageManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;
use Tests\Support\AppDevFakeSshExecutor;

it('converges the pinned Sury Resolute source before package installation', function (): void {
    $transport = new AppDevFakeSshExecutor;

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(RoleName::AppDev),
        collect(['8.4']),
        php_package_app_dev_ssh($transport),
    );

    expect($transport->commands)->toHaveCount(2);

    $sourceCommand = $transport->commands[0];
    $installCommand = $transport->commands[1];
    $sourceScript = $sourceCommand->input ?? '';
    $installScript = $installCommand->input ?? '';
    $firstSourceMutation = mb_strpos(haystack: $sourceScript, needle: 'sudo install');
    $releaseGuard = mb_strpos(
        haystack: $sourceScript,
        needle: '[ "${VERSION_CODENAME:-}" != "$expected_codename" ]',
    );

    expect(array_slice(array: $sourceCommand->arguments, offset: 0, length: 13))
        ->toBe([
            'bash',
            '-seu',
            '--',
            'ubuntu',
            'resolute',
            'https://packages.sury.org/php/',
            'https://packages.sury.org/php/apt.gpg',
            '/usr/share/keyrings/orbit-sury-php.gpg',
            '/etc/apt/sources.list.d/orbit-php.sources',
            'b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c',
            '15058500A0235D97F5D10063B188E2B695BD4743',
            '45BEA3E529112086C622F8A4B214EAC28059B8AC',
            '15058500A0235D97F5D10063B188E2B695BD4743',
        ])
        ->and($sourceScript)
        ->toContain(
            '[ ! -r /etc/os-release ]',
            '. /etc/os-release',
            '[ "${ID:-}" != "$expected_id" ]',
            '[ "${VERSION_CODENAME:-}" != "$expected_codename" ]',
            'ppa\\.launchpadcontent\\.net/ondrej/php',
            'packages\\.sury\\.org/php',
            '[ ! -e "$managed_path" ] && [ ! -L "$managed_path" ]',
            'umask 077',
            'mktemp -d',
            'gnupg_home="$work_directory/gnupg"',
            'install -d -m 0700 -- "$gnupg_home"',
            'curl --fail --silent --show-error --location --proto \'=https\' --tlsv1.2',
            'sha256sum',
            'GNUPGHOME="$gnupg_home" gpg --batch --with-colons --show-keys',
            'Types: deb',
            'Signed-By:',
            'trap restore_source EXIT',
            'install -m 0644 -o root -g root',
            'mv --',
            'apt-get -o DPkg::Lock::Timeout=300 update',
            'apt-cache policy',
            'apt-cache madison',
            'expected_origin="${expected_uri%/} $expected_codename/main"',
        )
        ->not->toContain('apt-key', 'add-apt-repository', 'ppa:ondrej/php', 'noble')->and(
            $releaseGuard,
        )->toBeInt()->toBeLessThan($firstSourceMutation)->and($firstSourceMutation)->toBeInt()->and(array_slice(
            array: $sourceCommand->arguments,
            offset: 13,
        ))->toBe(array_slice(array: $installCommand->arguments, offset: 5))->and(array_slice(
            array: $installCommand->arguments,
            offset: 0,
            length: 5,
        ))->toBe([
            'bash',
            '-seu',
            '--',
            '8.4',
            'app-dev',
        ])->and($installScript)->toContain('dpkg-query', 'apt-get -o DPkg::Lock::Timeout=300 install')
        ->not->toContain('[ -x "/usr/sbin/php-fpm$version" ]', 'apt-key', 'add-apt-repository');
});

it('uses exact Laravel package profiles without duplicates', function (string $role, string $version): void {
    $transport = new AppDevFakeSshExecutor;
    $nodeRole = $role === 'app-dev' ? RoleName::AppDev : RoleName::AppProd;
    $node = php_package_node($nodeRole);
    $manager = new RemotePhpPackageManager;

    $install = $role === 'app-dev'
        ? fn () => $manager->installForAppDev($node, collect([$version]), php_package_app_dev_ssh($transport))
        : fn () => $manager->installForAppProd($node, collect([$version]), php_package_app_prod_ssh($transport));
    $install();

    $sourcePackages = array_slice(array: $transport->commands[0]->arguments, offset: 13);
    $installPackages = array_slice(array: $transport->commands[1]->arguments, offset: 5);

    expect($sourcePackages)
        ->toBe(php_package_profile($version, $role))
        ->toBe($installPackages)
        ->toHaveCount(count(array_unique($sourcePackages)));
})->with([
    'app-dev PHP 8.4' => ['app-dev', '8.4'],
    'app-dev PHP 8.5' => ['app-dev', '8.5'],
    'app-dev future PHP' => ['app-dev', '8.6'],
    'app-prod PHP 8.4' => ['app-prod', '8.4'],
    'app-prod PHP 8.5' => ['app-prod', '8.5'],
    'app-prod future PHP' => ['app-prod', '8.6'],
]);

it('enables PCOV only for app-dev CLI and verifies both SAPIs', function (): void {
    $transport = new AppDevFakeSshExecutor;

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(RoleName::AppDev),
        collect(['8.5']),
        php_package_app_dev_ssh($transport),
    );

    $script = $transport->commands[1]->input ?? '';

    expect($script)
        ->toContain(
            'phpenmod -v "$version" -s cli pcov',
            'phpdismod -v "$version" -s fpm pcov',
            'php"$version" -m',
            'php-fpm"$version" -m',
            'systemctl enable --now "php$version-fpm.service"',
            'systemctl is-enabled --quiet "php$version-fpm.service"',
            'systemctl is-active --quiet "php$version-fpm.service"',
        )
        ->not->toContain('xdebug', 'opentelemetry');
});

it('does not request or enable PCOV for a pure app-prod node', function (): void {
    $transport = new AppDevFakeSshExecutor;

    new RemotePhpPackageManager()->installForAppProd(
        php_package_node(RoleName::AppProd),
        collect(['8.5']),
        php_package_app_prod_ssh($transport),
    );

    expect(php_package_scripts($transport))
        ->toContain('if printf \'%s\\n\' "$cli_modules" | grep -qxF pcov')
        ->not->toContain(
            'phpenmod -v "$version" -s cli pcov',
            'phpdismod -v "$version" -s fpm pcov',
            'xdebug',
            'opentelemetry',
        )->and(implode(' ', $transport->commands[1]->arguments))
        ->not->toContain('pcov');
});

it('keeps PCOV when app-prod convergence targets a dual-role node', function (): void {
    $transport = new AppDevFakeSshExecutor;
    $node = php_package_node(RoleName::AppProd);
    $node->roles()->create(['role' => RoleName::AppDev]);

    new RemotePhpPackageManager()->installForAppProd(
        $node->load('roles'),
        collect(['8.5']),
        php_package_app_prod_ssh($transport),
    );

    expect(array_slice(array: $transport->commands[1]->arguments, offset: 5))
        ->toContain('php8.5-pcov')
        ->and($transport->commands[1]->input)
        ->toContain('phpenmod -v "$version" -s cli pcov', 'phpdismod -v "$version" -s fpm pcov');
});

it('maps source failures to the stable role-specific contract', function (string $role): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(1, '', 'Orbit requires Ubuntu 26.04 Resolute.', 1, false),
    ]);
    $manager = new RemotePhpPackageManager;
    $nodeRole = $role === 'app-dev' ? RoleName::AppDev : RoleName::AppProd;

    $operation = $role === 'app-dev'
        ? fn () => $manager->installForAppDev(
            php_package_node($nodeRole),
            collect(['8.5']),
            php_package_app_dev_ssh($transport),
        )
        : fn () => $manager->installForAppProd(
            php_package_node($nodeRole),
            collect(['8.5']),
            php_package_app_prod_ssh($transport),
        );

    expect($operation)->toThrow(function (RuntimeConvergenceException $exception) use ($role): void {
        expect($exception->step)
            ->toBe($role === 'app-dev' ? 'php-package-source' : 'app-prod-php-package-source')
            ->and($exception->errorCode)
            ->toBe(
                $role === 'app-dev'
                    ? 'app-dev.php_package_source_unavailable'
                    : 'app-prod.php_package_source_unavailable',
            );
    });

    expect($transport->commands)->toHaveCount(1);
})->with(['app-dev', 'app-prod']);

it('retains valid source state and partial packages when installation fails', function (): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'package install failed', 1, false),
    ]);

    expect(fn () => new RemotePhpPackageManager()->installForAppDev(
        php_package_node(RoleName::AppDev),
        collect(['8.5']),
        php_package_app_dev_ssh($transport),
    ))->toThrow(function (RuntimeConvergenceException $exception): void {
        expect($exception->step)
            ->toBe('php-fpm-install')
            ->and($exception->errorCode)
            ->toBe('app-dev.php_install_failed');
    });

    expect($transport->commands)
        ->toHaveCount(2)
        ->and($transport->commands[0]->input)
        ->toContain('trap restore_source EXIT')
        ->and($transport->commands[1]->input)
        ->not->toContain('apt-get remove', 'rm -f /usr/share/keyrings/orbit-sury-php.gpg');
});

it('performs no remote work for an empty version collection', function (): void {
    $transport = new AppDevFakeSshExecutor;

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(RoleName::AppDev),
        collect(),
        php_package_app_dev_ssh($transport),
    );

    expect($transport->commands)->toBeEmpty();
});

it('renders syntactically valid fixed shell programs', function (): void {
    $transport = new AppDevFakeSshExecutor;

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(RoleName::AppDev),
        collect(['8.4', '8.5']),
        php_package_app_dev_ssh($transport),
    );

    foreach ($transport->commands as $command) {
        $process = new Process(['bash', '-n']);
        $process->setInput($command->input ?? '');
        $process->run();

        expect($process->isSuccessful())
            ->toBeTrue(
                $process->getErrorOutput()."\n".($command->input ?? ''),
            );
    }
});

function php_package_node(RoleName $role): Node
{
    $count = Node::query()->count();
    $node = Node::query()->create([
        'name' => 'php-package-node-'.str_replace(search: '-', replace: '', subject: $role->value)."-{$count}",
        'platform' => 'linux',
        'architecture' => 'x86_64',
        'public_ssh_host' => '192.0.2.44',
        'wireguard_address' => '10.44.0.'.(44 + $count),
        'ssh_user' => 'orbit',
    ]);
    $node->roles()->create(['role' => $role]);

    return $node->load('roles');
}

function php_package_app_dev_ssh(AppDevFakeSshExecutor $transport): AppDevSshExecutor
{
    return new AppDevSshExecutor(
        ssh: $transport,
        keys: php_package_keys(),
        knownHosts: php_package_known_hosts(),
    );
}

function php_package_app_prod_ssh(AppDevFakeSshExecutor $transport): AppProdSshExecutor
{
    return new AppProdSshExecutor(
        ssh: $transport,
        keys: php_package_keys(),
        knownHosts: php_package_known_hosts(),
    );
}

function php_package_keys(): SshKeyProvider
{
    return new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/tmp/orbit-test-key';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 TEST';
        }
    };
}

function php_package_known_hosts(): KnownHostsStore
{
    return new class implements KnownHostsStore {
        public function path(): string
        {
            return '/tmp/orbit-test-known-hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };
}

/** @return list<string> */
function php_package_profile(string $version, string $profile): array
{
    $suffixes = [
        'cli',
        'fpm',
        'common',
        'bcmath',
        'curl',
        'gd',
        'imagick',
        'intl',
        'mbstring',
        'mysql',
        'pgsql',
        'redis',
        'sqlite3',
        'xml',
        'zip',
    ];

    if ($version === '8.4') {
        $suffixes[] = 'opcache';
    }

    if ($profile === 'app-dev') {
        $suffixes[] = 'pcov';
    }

    return array_map(static fn (string $suffix): string => "php{$version}-{$suffix}", $suffixes);
}

function php_package_scripts(AppDevFakeSshExecutor $transport): string
{
    return Collection::make($transport->commands)
        ->map(static fn (RemoteCommand $command): string => $command->input ?? '')
        ->implode("\n");
}
