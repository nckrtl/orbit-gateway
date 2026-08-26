<?php

declare(strict_types=1);

use App\Domain\Processes\ProcessTarget;
use App\Infrastructure\Processes\SystemdProcessRenderer;
use App\Models\Node;
use App\Models\Process;

it('renders an Orbit-owned systemd unit with fixed argv and the target identity', function (): void {
    $node = new Node(['name' => 'production', 'wireguard_address' => '10.44.0.4']);
    $process = new Process([
        'name' => 'queue',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work', '--queue=high priority', '$LITERAL', '%n'],
            'environment_file' => '/var/www/docs/main/.env',
        ],
        'working_directory' => '/var/www/docs/main',
        'restart_policy' => 'on-failure',
    ]);
    $process->id = 17;
    $target = new ProcessTarget(
        node: $node,
        user: 'orbit-docs',
        checkoutPath: '/var/www/docs/main',
    );

    $renderer = new SystemdProcessRenderer;
    $unit = $renderer->render($process, $target);

    expect($renderer->unitName($process))
        ->toBe('orbit-process-17-queue.service')
        ->and($unit)
        ->toContain('X-Orbit-Process-ID=17')
        ->toContain('User=orbit-docs')
        ->toContain('WorkingDirectory=/var/www/docs/main')
        ->toContain('EnvironmentFile=-/var/www/docs/main/.env')
        ->toContain('ExecStart="/usr/bin/php" "artisan" "queue:work" "--queue=high priority" "$$LITERAL" "%%n"')
        ->toContain('Restart=on-failure')
        ->not->toContain('/bin/bash')
        ->not->toContain('sh -c');
});

it('maps common restart policies to valid systemd values', function (string $policy, string $expected): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'command' => ['/usr/bin/sleep', '60'],
            'environment_file' => '/home/orbit/apps/docs/.env',
        ],
        'working_directory' => '/home/orbit/apps/docs',
        'restart_policy' => $policy,
    ]);
    $process->id = 2;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    expect(new SystemdProcessRenderer()->render($process, $target))->toContain("Restart={$expected}");
})->with([
    'never' => ['never', 'no'],
    'on failure' => ['on-failure', 'on-failure'],
    'always' => ['always', 'always'],
    'unless stopped' => ['unless-stopped', 'always'],
]);

it('systemd-escapes accepted working and environment file paths with spaces', function (): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan'],
            'environment_file' => '/home/orbit/Work Trees/docs/.env',
        ],
        'working_directory' => '/home/orbit/Work Trees/docs',
        'restart_policy' => 'never',
    ]);
    $process->id = 3;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/Work Trees/docs',
    );

    expect(new SystemdProcessRenderer()->render($process, $target))
        ->toContain('WorkingDirectory=/home/orbit/Work\\x20Trees/docs')
        ->toContain('EnvironmentFile=-/home/orbit/Work\\x20Trees/docs/.env');
});

it('rejects a non-absolute executable from persisted runtime configuration', function (): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'command' => ['php', 'artisan'],
            'environment_file' => '/home/orbit/apps/docs/.env',
        ],
        'working_directory' => '/home/orbit/apps/docs',
        'restart_policy' => 'never',
    ]);
    $process->id = 4;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    expect(fn () => new SystemdProcessRenderer()->render($process, $target))
        ->toThrow(InvalidArgumentException::class, 'absolute executable');
});
