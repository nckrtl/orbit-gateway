<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Infrastructure\Nodes\Roles\NodeRolePrerequisiteCommandFactory;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

it('uses fixed package lists for every role', function (): void {
    expect(class_exists(NodeRolePrerequisiteCommandFactory::class))->toBeTrue();

    $factory = new NodeRolePrerequisiteCommandFactory;

    expect(array_slice($factory->make(RoleName::AppDev)->arguments, offset: 5))
        ->toBe(['acl', 'attr', 'caddy', 'composer', 'docker.io', 'git', 'openssl', 'unzip'])
        ->and(array_slice($factory->make(RoleName::AppProd)->arguments, offset: 5))
        ->toBe(['acl', 'attr', 'caddy', 'composer', 'docker.io', 'git', 'openssl', 'unzip'])
        ->and(array_slice($factory->make(RoleName::Vpn)->arguments, offset: 5))
        ->toBe(['dnsmasq', 'openssl'])
        ->and($factory->make(RoleName::Gateway)->arguments)
        ->toBe(['true']);
});

it('keeps app development directories and Caddy traversal ACLs role-owned', function (): void {
    expect(class_exists(NodeRolePrerequisiteCommandFactory::class))->toBeTrue();

    $factory = new NodeRolePrerequisiteCommandFactory;
    $appDev = $factory->make(RoleName::AppDev)->input ?? '';
    $appProd = $factory->make(RoleName::AppProd)->input ?? '';
    $vpn = $factory->make(RoleName::Vpn)->input ?? '';

    expect($appDev)
        ->toContain(
            'install -d -m 0755 -o orbit -g orbit /home/orbit/apps /home/orbit/.orbit/worktrees',
            'setfacl -m u:caddy:--x /home/orbit /home/orbit/apps /home/orbit/.orbit /home/orbit/.orbit/worktrees',
        )
        ->and($appProd)
        ->not->toContain('/home/orbit/apps', 'setfacl')->and($vpn)
        ->not->toContain('/home/orbit/apps', '/opt/orbit/vite-plus', '/opt/orbit/bun');
});

it('preserves the complete Vite Plus and Bun application-host runtime', function (RoleName $role): void {
    expect(class_exists(NodeRolePrerequisiteCommandFactory::class))->toBeTrue();

    $script = new NodeRolePrerequisiteCommandFactory()->make($role)->input ?? '';
    $syntax = new Process(['bash', '-n']);
    $syntax->setInput($script);
    $syntax->run();

    expect($script)
        ->toContain(
            'VP_HOME=/opt/orbit/vite-plus',
            'https://vite.plus',
            'env setup',
            'env on',
            'env install lts',
            'env default lts',
            'install -g --node lts pnpm',
            'BUN_INSTALL=/opt/orbit/bun',
            'https://bun.com/install',
            '/usr/local/bin/vp',
            '/usr/local/bin/node',
            '/usr/local/bin/pnpm',
            '/usr/local/bin/npm',
            '/usr/local/bin/npx',
            '/usr/local/bin/bun',
            'export VP_HOME=/opt/orbit/vite-plus',
            'Orbit JavaScript runtime directory conflict:',
            'Orbit JavaScript runtime launcher conflict:',
            'Orbit JavaScript runtime link conflict:',
            'rollback_javascript_runtime()',
        )
        ->not
        ->toContain('vp env install bun', 'npm install -g', 'bun install')
        ->and($syntax->isSuccessful())
        ->toBeTrue($syntax->getErrorOutput());
})->with([
    'app development' => RoleName::AppDev,
    'app production' => RoleName::AppProd,
]);

it('propagates failures from both official runtime installer downloads', function (): void {
    expect(class_exists(NodeRolePrerequisiteCommandFactory::class))->toBeTrue();

    $script = new NodeRolePrerequisiteCommandFactory()->make(RoleName::AppDev)->input ?? '';

    foreach (['https://vite.plus', 'https://bun.com/install'] as $installerUrl) {
        $installerLine = collect(preg_split('/\R/', $script))
            ->first(static fn (string $line): bool => str_contains($line, $installerUrl));

        expect($installerLine)
            ->toBeString()
            ->toContain('bash -o pipefail -lc');

        $failureCommand = preg_replace(
            pattern: '/^sudo -u orbit -H env \S+ /',
            replacement: '',
            subject: trim($installerLine),
        );
        $failureCommand = str_replace(
            search: "curl -fsSL {$installerUrl}",
            replace: 'false',
            subject: $failureCommand ?? '',
        );
        $failure = Process::fromShellCommandline($failureCommand);
        $failure->run();

        expect($failure->isSuccessful())->toBeFalse();
    }
});

it('guards managed JavaScript paths before publishing stable entry points', function (): void {
    $script = new NodeRolePrerequisiteCommandFactory()->make(RoleName::AppProd)->input ?? '';
    $runtimeGuard = mb_strpos(haystack: $script, needle: 'Orbit JavaScript runtime directory conflict:');
    $runtimeCreation = mb_strpos(haystack: $script, needle: 'install -d -m 0755 /opt/orbit');
    $candidateCreation = mb_strpos(
        haystack: $script,
        needle: 'launcher_candidates=$(mktemp -d "/usr/local/bin/.orbit-js-runtime.XXXXXX")',
    );
    $launcherGuard = mb_strpos(haystack: $script, needle: 'Orbit JavaScript runtime launcher conflict:');
    $bunGuard = mb_strpos(haystack: $script, needle: 'Orbit JavaScript runtime link conflict:');
    $launcherPublish = mb_strpos(haystack: $script, needle: 'mv "$candidate" "$launcher"');
    $bunPublish = mb_strpos(haystack: $script, needle: 'ln -s "$bun_binary" /usr/local/bin/bun');

    expect($script)->toContain(
        'stat -c \'%U:%G\' /opt/orbit',
        'stat -c \'%U:%G\' "$directory"',
        'stat -c \'%U:%G\' "$launcher"',
        'stat -c \'%a\' "$launcher"',
        'stat -c \'%U:%G\' /usr/local/bin/bun',
        'cmp -s "$launcher" "$candidate"',
        'published_paths=',
        'rollback_javascript_runtime()',
        'rm -f -- "$published_path"',
    );
    expect($runtimeGuard)->toBeInt()->toBeLessThan($runtimeCreation);
    expect($runtimeCreation)->toBeInt()->toBeLessThan($candidateCreation);
    expect($candidateCreation)->toBeInt()->toBeLessThan($launcherGuard);
    expect($launcherGuard)->toBeInt()->toBeLessThan($launcherPublish);
    expect($bunGuard)->toBeInt()->toBeLessThan($launcherPublish);
    expect($bunGuard)->toBeInt()->toBeLessThan($bunPublish);
    expect(substr_count(haystack: $script, needle: '> "$candidate"'))->toBe(1);
});

it('rejects foreign launchers before publishing stable entry points', function (): void {
    expect(class_exists(NodeRolePrerequisiteCommandFactory::class))->toBeTrue();

    $script = new NodeRolePrerequisiteCommandFactory()->make(RoleName::AppProd)->input ?? '';
    $harness = role_javascript_runtime_harness($script, foreignLauncher: 'npm');

    try {
        expect($harness['process']->isSuccessful())
            ->toBeFalse()
            ->and($harness['process']->getErrorOutput())
            ->toContain("Orbit JavaScript runtime launcher conflict: {$harness['stableDirectory']}/npm")
            ->and(file_get_contents("{$harness['stableDirectory']}/npm"))
            ->toBe("foreign\n");

        foreach (['vp', 'node', 'pnpm', 'npx', 'bun'] as $binary) {
            expect("{$harness['stableDirectory']}/{$binary}")->not->toBeFile();
        }
    } finally {
        new Filesystem()->deleteDirectory($harness['root']);
    }
});

it('preserves exact launchers while rolling back new entry points after verification fails', function (): void {
    $script = new NodeRolePrerequisiteCommandFactory()->make(RoleName::AppDev)->input ?? '';
    $harness = role_javascript_runtime_harness($script, failingRuntime: 'npx', exactLauncher: 'vp');

    try {
        expect($harness['process']->isSuccessful())
            ->toBeFalse()
            ->and(file_get_contents("{$harness['stableDirectory']}/vp"))
            ->toBe($harness['exactLauncherContents']);

        foreach (['node', 'pnpm', 'npm', 'npx', 'bun'] as $binary) {
            expect("{$harness['stableDirectory']}/{$binary}")->not->toBeFile();
        }
    } finally {
        new Filesystem()->deleteDirectory($harness['root']);
    }
});

/**
 * @return array{root: string, stableDirectory: string, exactLauncherContents: string, process: Process}
 */
function role_javascript_runtime_harness(
    string $script,
    ?string $foreignLauncher = null,
    ?string $failingRuntime = null,
    ?string $exactLauncher = null,
): array {
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-role-javascript-runtime-'.Str::random(16);
    $sourceDirectory = "{$root}/source";
    $stableDirectory = "{$root}/stable";
    $filesystem->makeDirectory($sourceDirectory, 0o700, recursive: true);
    $filesystem->makeDirectory($stableDirectory, 0o700, recursive: true);

    foreach (['vp', 'node', 'pnpm', 'npm', 'npx', 'bun'] as $binary) {
        $exitCode = $binary === $failingRuntime ? 1 : 0;
        $filesystem->put("{$sourceDirectory}/{$binary}", "#!/bin/sh\nexit {$exitCode}\n");
        chmod(filename: "{$sourceDirectory}/{$binary}", permissions: 0o755);
    }

    $exactLauncherContents = '';

    if ($exactLauncher !== null) {
        $exactLauncherContents = "#!/bin/sh\nexport VP_HOME=/opt/orbit/vite-plus\nexec \"{$sourceDirectory}/{$exactLauncher}\" \"\$@\"\n";
        $filesystem->put("{$stableDirectory}/{$exactLauncher}", $exactLauncherContents);
        chmod(filename: "{$stableDirectory}/{$exactLauncher}", permissions: 0o755);
    }

    if ($foreignLauncher !== null) {
        $filesystem->put("{$stableDirectory}/{$foreignLauncher}", "foreign\n");
        chmod(filename: "{$stableDirectory}/{$foreignLauncher}", permissions: 0o755);
    }

    $start = mb_strpos(
        haystack: $script,
        needle: 'launcher_candidates=$(mktemp -d "/usr/local/bin/.orbit-js-runtime.XXXXXX")',
    );
    $end = is_int($start) ? mb_strpos(haystack: $script, needle: 'trap - EXIT', offset: $start) : false;

    if (! is_int($start) || ! is_int($end)) {
        throw new RuntimeException('Could not isolate the JavaScript runtime publication block.');
    }

    $publicationScript = mb_substr(
        string: $script,
        start: $start,
        length: $end - $start + mb_strlen('trap - EXIT'),
    );
    $owner = posix_getpwuid(fileowner($stableDirectory));
    $group = posix_getgrgid(filegroup($stableDirectory));

    if (! is_array($owner) || ! is_array($group)) {
        throw new RuntimeException('Could not resolve the JavaScript runtime harness owner.');
    }

    $publicationScript = str_replace(
        ['/opt/orbit/vite-plus/bin', '/usr/local/bin', "'root:root'", 'chown root:root "$candidate"'],
        [$sourceDirectory, $stableDirectory, "'{$owner['name']}:{$group['name']}'", 'true'],
        $publicationScript,
    );
    $process = new Process(['bash', '-seu']);
    $process->setInput("bun_binary={$sourceDirectory}/bun\n{$publicationScript}\n");
    $process->run();

    return [
        'root' => $root,
        'stableDirectory' => $stableDirectory,
        'exactLauncherContents' => $exactLauncherContents,
        'process' => $process,
    ];
}
