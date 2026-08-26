<?php

declare(strict_types=1);

use App\Domain\Processes\ProcessTarget;
use App\Infrastructure\Processes\DockerProcessRenderer;
use App\Models\Node;
use App\Models\Process;

it('renders one collision-safe Orbit-owned Docker container with explicit runtime input', function (): void {
    $process = new Process([
        'name' => 'queue',
        'runtime_config' => [
            'image' => 'redis:8-alpine',
            'command' => ['redis-server', '--save', ''],
            'environment' => ['QUEUE_NAME' => 'critical jobs'],
            'ports' => ['127.0.0.1:6380:6379/tcp'],
            'volumes' => [
                ['source' => 'redis-data', 'target' => '/data', 'read_only' => false],
                ['source' => '/home/orbit/redis.conf', 'target' => '/etc/redis.conf', 'read_only' => true],
            ],
        ],
        'working_directory' => '/data',
        'restart_policy' => 'unless-stopped',
    ]);
    $process->id = 41;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    $renderer = new DockerProcessRenderer;
    $arguments = $renderer->createArguments($process, $target);
    $environmentInput = $renderer->environmentInput($process);

    expect($renderer->containerName($process))
        ->toBe('orbit-process-41-queue')
        ->and($arguments)
        ->toBe([
            'sudo',
            'docker',
            'container',
            'create',
            '--name',
            'orbit-process-41-queue',
            '--label',
            'orbit.managed=true',
            '--label',
            'orbit.container.kind=process',
            '--label',
            'orbit.process.id=41',
            '--label',
            'orbit.process.spec='.$renderer->specHash($process, $target),
            '--restart',
            'unless-stopped',
            '--workdir',
            '/data',
            '--publish',
            '127.0.0.1:6380:6379/tcp',
            '--mount',
            'type=volume,source=redis-data,target=/data',
            '--mount',
            'type=bind,source=/home/orbit/redis.conf,target=/etc/redis.conf,readonly',
            'redis:8-alpine',
            'redis-server',
            '--save',
            '',
        ])
        ->and(implode("\0", $arguments))
        ->not
        ->toContain('critical jobs')
        ->and(stream_get_contents($environmentInput->stream()))
        ->toBe("QUEUE_NAME=critical jobs\n");

    $environmentInput->close();
});

it('does not require the managed SSH user to belong to the Docker group', function (): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => ['image' => 'busybox:1', 'command' => ['sleep', '60']],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $process->id = 9;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    expect(array_slice(new DockerProcessRenderer()->createArguments($process, $target), offset: 0, length: 4))
        ->toBe(['sudo', 'docker', 'container', 'create']);
});

it('uses canonical Docker environment order for arguments and specification hashes', function (): void {
    $first = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => ['ZEBRA' => 'last', 'ALPHA' => 'first'],
        ],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $first->id = 9;
    $second = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => ['ALPHA' => 'first', 'ZEBRA' => 'last'],
        ],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $second->id = 9;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );
    $renderer = new DockerProcessRenderer;
    $firstInput = $renderer->environmentInput($first);
    $secondInput = $renderer->environmentInput($second);

    expect($renderer->specHash($first, $target))
        ->toBe($renderer->specHash($second, $target))
        ->and($renderer->createArguments($first, $target))
        ->toBe($renderer->createArguments($second, $target))
        ->and(stream_get_contents($firstInput->stream()))
        ->toBe("ALPHA=first\nZEBRA=last\n")
        ->and(stream_get_contents($secondInput->stream()))
        ->toBe("ALPHA=first\nZEBRA=last\n");

    $firstInput->close();
    $secondInput->close();
});

it('rejects an option-like image from persisted runtime configuration', function (): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => ['image' => '--privileged', 'command' => ['sleep', '60']],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $process->id = 10;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    expect(fn () => new DockerProcessRenderer()->createArguments($process, $target))
        ->toThrow(InvalidArgumentException::class, 'image');
});

it('rejects unsafe Docker environment input from persisted configuration', function (array $environment): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => $environment,
        ],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $process->id = 10;

    expect(fn () => new DockerProcessRenderer()->environmentInput($process))
        ->toThrow(InvalidArgumentException::class, 'environment');
})->with([
    'unsafe name' => [['BAD-NAME' => 'value']],
    'leading digit' => [['1APP_KEY' => 'value']],
    'assignment in name' => [['APP=KEY' => 'value']],
    'line feed' => [['APP_KEY' => "first\nsecond"]],
    'carriage return' => [['APP_KEY' => "first\rsecond"]],
    'null byte' => [['APP_KEY' => "first\0second"]],
]);

it('rejects a non-map Docker environment from persisted configuration', function (): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => 'APP_KEY=unsafe-shape',
        ],
        'working_directory' => '/work',
        'restart_policy' => 'never',
    ]);
    $process->id = 10;

    expect(fn () => new DockerProcessRenderer()->environmentInput($process))
        ->toThrow(InvalidArgumentException::class, 'environment');
});

it('maps common restart policies to Docker restart policies', function (string $policy, string $expected): void {
    $process = new Process([
        'name' => 'worker',
        'runtime_config' => ['image' => 'busybox:1', 'command' => ['sleep', '60']],
        'working_directory' => '/work',
        'restart_policy' => $policy,
    ]);
    $process->id = 2;
    $target = new ProcessTarget(
        node: new Node(['name' => 'dev']),
        user: 'orbit',
        checkoutPath: '/home/orbit/apps/docs',
    );

    expect(new DockerProcessRenderer()->createArguments($process, $target))->toContain($expected);
})->with([
    'never' => ['never', 'no'],
    'on failure' => ['on-failure', 'on-failure'],
    'always' => ['always', 'always'],
    'unless stopped' => ['unless-stopped', 'unless-stopped'],
]);
