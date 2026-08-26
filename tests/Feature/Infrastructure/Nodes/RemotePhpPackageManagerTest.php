<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\Nodes\RemotePhpPackageManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use Illuminate\Support\Collection;
use Tests\Support\AppDevFakeSshExecutor;

it('adds the documented Noble PHP source only after existing candidates are unavailable', function (): void {
    $node = php_package_node();
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "ubuntu\nnoble\n", '', 1, false),
    ]);

    new RemotePhpPackageManager()->installForAppDev(
        $node,
        collect(['8.4']),
        php_package_app_dev_ssh($transport),
    );

    $sourceCommand = $transport->commands[3];
    $candidateCommand = $transport->commands[4];
    $installCommand = $transport->commands[5];
    $sourceScript = $sourceCommand->input ?? '';
    $codenameGuard = mb_strpos(
        haystack: $sourceScript,
        needle: '[ "${VERSION_CODENAME:-}" != "$expected_codename" ]',
    );
    $firstMutation = mb_strpos(haystack: $sourceScript, needle: 'sudo env DEBIAN_FRONTEND');

    expect($transport->commands)
        ->toHaveCount(6)
        ->and($transport->commands[0]->input)
        ->toContain('[ ! -x "/usr/sbin/php-fpm$version" ]')
        ->not->toContain('command -v')->and($transport->commands[1]->input)->toContain(
            'for suffix in cli curl fpm intl mbstring sqlite3 xml zip',
            'package="php$version-$suffix"',
            'apt-cache policy -- "$package"',
            '[ "$candidate" = \'(none)\' ]',
            'printf \'%s\n\' "$version"',
        )
        ->not->toContain('add-apt-repository')->and($sourceCommand->arguments)->toBe([
            'bash',
            '-seu',
            '--',
            'noble',
            'ondrej/php',
        ])->and($sourceScript)->toContain(
            '. /etc/os-release',
            '[ "${ID:-}" != ubuntu ]',
            '[ "${VERSION_CODENAME:-}" != "$expected_codename" ]',
            'apt-get -o DPkg::Lock::Timeout=300 update',
            'apt-get -o DPkg::Lock::Timeout=300 install',
            'software-properties-common',
            'sudo env LC_ALL=C.UTF-8 add-apt-repository --yes --no-update "ppa:$ppa"',
        )
        ->not->toContain(
            'curl ',
            'wget ',
            'jammy',
            'resolute',
            'devel',
            'gpg ',
            '.sources',
        )->and($candidateCommand->arguments)->toBe([
            'bash',
            '-seu',
            '--',
            'https://ppa.launchpadcontent.net/ondrej/php/ubuntu/',
            'noble',
            '8.4',
        ])->and($candidateCommand->input)->toContain(
            'for suffix in cli curl fpm intl mbstring sqlite3 xml zip',
            'package="php$version-$suffix"',
            'apt-cache policy -- "$package"',
            'apt-cache madison -- "$package"',
            'expected_origin="${expected_uri%/} $expected_codename/main"',
        )->and($installCommand->arguments)->toBe(['bash', '-seu', '--', '8.4'])->and($installCommand->input)->toContain(
            '[ -x "/usr/sbin/php-fpm$version" ]',
            'apt-get -o DPkg::Lock::Timeout=300 install',
            '"php$version-cli"',
            '"php$version-curl"',
            '"php$version-fpm"',
            '"php$version-intl"',
            '"php$version-mbstring"',
            '"php$version-sqlite3"',
            '"php$version-xml"',
            '"php$version-zip"',
        )->and($codenameGuard)->toBeInt()->toBeLessThan($firstMutation)->and($firstMutation)->toBeInt();
});

it('installs a missing Resolute default from existing Ubuntu sources without PPA mutation', function (): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.5\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ]);

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(),
        collect(['8.5']),
        php_package_app_dev_ssh($transport),
    );

    $scripts = php_package_scripts($transport);

    expect($transport->commands)
        ->toHaveCount(3)
        ->and($transport->commands[2]->arguments)
        ->toBe(['bash', '-seu', '--', '8.5'])
        ->and($scripts)
        ->toContain('"php$version-fpm"')
        ->not->toContain('/etc/os-release', 'add-apt-repository', 'ondrej/php', 'noble');
});

it('rejects a missing Resolute non-default before repository or package mutation', function (): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "ubuntu\nresolute\n", '', 1, false),
    ]);

    expect(fn () => new RemotePhpPackageManager()->installForAppDev(
        php_package_node(),
        collect(['8.4']),
        php_package_app_dev_ssh($transport),
    ))->toThrow(function (RuntimeConvergenceException $exception): void {
        expect($exception->getMessage())
            ->toBe('The PHP package source is unavailable for this host.')
            ->and($exception->step)
            ->toBe('php-package-source')
            ->and($exception->errorCode)
            ->toBe('app-dev.php_package_source_unavailable');
    });

    expect($transport->commands)
        ->toHaveCount(3)
        ->and(php_package_scripts($transport))
        ->not->toContain('sudo ', 'apt-get', 'add-apt-repository', 'ondrej/php', 'noble', 'devel');
});

it('rejects unsupported or malformed hosts before repository or package mutation', function (string $release): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, $release, '', 1, false),
    ]);

    expect(fn () => new RemotePhpPackageManager()->installForAppDev(
        php_package_node(),
        collect(['8.4']),
        php_package_app_dev_ssh($transport),
    ))
        ->toThrow(RuntimeConvergenceException::class);

    expect(php_package_scripts($transport))->not->toContain('sudo ', 'apt-get', 'add-apt-repository', 'ondrej/php');
})->with([
    'non-Ubuntu' => "debian\nbookworm\n",
    'missing codename' => "ubuntu\n",
    'malformed release' => "unexpected\nextra\nfields\n",
]);

it('does no source or package work when every requested FPM binary exists', function (): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, '', '', 1, false),
    ]);

    new RemotePhpPackageManager()->installForAppDev(
        php_package_node(),
        collect(['8.4', '8.5']),
        php_package_app_dev_ssh($transport),
    );

    expect($transport->commands)
        ->toHaveCount(1)
        ->and(php_package_scripts($transport))
        ->not->toContain('/etc/os-release', 'apt-cache', 'apt-get', 'add-apt-repository');
});

it('retains the source error when the configured version has no verified PPA candidate', function (): void {
    $transport = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "ubuntu\nnoble\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Candidate: (none)', 1, false),
    ]);

    expect(fn () => new RemotePhpPackageManager()->installForAppDev(
        php_package_node(),
        collect(['8.4']),
        php_package_app_dev_ssh($transport),
    ))->toThrow(function (RuntimeConvergenceException $exception): void {
        expect($exception->step)
            ->toBe('php-package-source')
            ->and($exception->errorCode)
            ->toBe('app-dev.php_package_source_unavailable');
    });

    expect($transport->commands)
        ->toHaveCount(5)
        ->and($transport->commands[4]->input)
        ->toContain('apt-cache madison', 'expected_origin')
        ->and(collect($transport->commands)->slice(5))
        ->toBeEmpty();
});

it('uses the same idempotent documented source command on retry', function (): void {
    $successfulRun = [
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "ubuntu\nnoble\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ];
    $transport = new AppDevFakeSshExecutor([...$successfulRun, ...$successfulRun]);
    $manager = new RemotePhpPackageManager;
    $node = php_package_node();
    $ssh = php_package_app_dev_ssh($transport);

    $manager->installForAppDev($node, collect(['8.4']), $ssh);
    $manager->installForAppDev($node, collect(['8.4']), $ssh);

    $sourceCommands = collect($transport->commands)
        ->filter(static fn (RemoteCommand $command): bool => str_contains(
            haystack: $command->input ?? '',
            needle: 'LC_ALL=C.UTF-8 add-apt-repository',
        ))
        ->values();

    expect($sourceCommands)
        ->toHaveCount(2)
        ->and($sourceCommands[0]->arguments)
        ->toBe($sourceCommands[1]->arguments)
        ->and($sourceCommands[0]->input)
        ->toBe($sourceCommands[1]->input)
        ->toContain('add-apt-repository --yes --no-update "ppa:$ppa"');
});

function php_package_node(): Node
{
    return Node::query()->create([
        'name' => 'php-package-node',
        'public_ssh_host' => '192.0.2.44',
        'wireguard_address' => '10.44.0.44',
        'ssh_user' => 'orbit',
    ]);
}

function php_package_app_dev_ssh(AppDevFakeSshExecutor $transport): AppDevSshExecutor
{
    return new AppDevSshExecutor(
        ssh: $transport,
        keys: new class implements SshKeyProvider {
            public function privateKeyPath(): string
            {
                return '/tmp/orbit-test-key';
            }

            public function publicKey(): string
            {
                return 'ssh-ed25519 TEST';
            }
        },
        knownHosts: new class implements KnownHostsStore {
            public function path(): string
            {
                return '/tmp/orbit-test-known-hosts';
            }

            public function put(string $host, int $port, HostKey $key): void {}
        },
    );
}

function php_package_scripts(AppDevFakeSshExecutor $transport): string
{
    return Collection::make($transport->commands)
        ->map(static fn (RemoteCommand $command): string => $command->input ?? '')
        ->implode("\n");
}
