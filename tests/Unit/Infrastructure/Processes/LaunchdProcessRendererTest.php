<?php

declare(strict_types=1);

use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessTarget;
use App\Infrastructure\Processes\LaunchdProcessRenderer;
use App\Models\Node;
use App\Models\Process;

it('renders an orbit-owned launchd plist without a shell wrapper', function (): void {
    $process = new Process([
        'name' => 'queue',
        'runtime' => ProcessRuntime::Launchd,
        'working_directory' => '/Users/nckrtl/apps/docs',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work', '--sleep=1'],
            'environment' => ['APP_ENV' => 'local'],
        ],
        'restart_policy' => 'on-failure',
    ]);
    $process->id = 42;
    $target = new ProcessTarget(
        node: new Node(['platform' => 'darwin']),
        user: 'nckrtl',
        checkoutPath: '/Users/nckrtl/apps/docs',
    );

    $plist = new LaunchdProcessRenderer()->render($process, $target);

    expect($plist)
        ->toContain('<?xml version="1.0" encoding="UTF-8"?>')
        ->toContain('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"')
        ->toContain('<string>dev.orbit.process.42.queue</string>')
        ->toContain('<string>/usr/bin/php</string>')
        ->toContain('<string>artisan</string>')
        ->toContain('<string>queue:work</string>')
        ->toContain('<key>APP_ENV</key>')
        ->toContain('<string>local</string>')
        ->toContain('<key>SuccessfulExit</key>')
        ->toContain('/Users/nckrtl/Library/Logs/Orbit/processes/dev.orbit.process.42.queue.stdout.log')
        ->not->toContain('/bin/bash')
        ->not->toContain('bash -lc');
});

it('rejects unsafe persisted launchd environment values', function (): void {
    $process = new Process([
        'name' => 'queue',
        'runtime' => ProcessRuntime::Launchd,
        'working_directory' => '/Users/nckrtl/apps/docs',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan'],
            'environment' => ['APP_KEY' => "bad\nvalue"],
        ],
        'restart_policy' => 'never',
    ]);
    $process->id = 7;

    expect(fn (): string => new LaunchdProcessRenderer()->render(
        $process,
        new ProcessTarget(new Node(['platform' => 'darwin']), 'nckrtl', '/Users/nckrtl/apps/docs'),
    ))
        ->toThrow(InvalidArgumentException::class);
});

it('keeps controlled home and path authoritative over process environment', function (): void {
    $process = new Process([
        'name' => 'queue',
        'runtime' => ProcessRuntime::Launchd,
        'working_directory' => '/Users/nckrtl/apps/docs',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan'],
            'environment' => [
                'HOME' => '/tmp/caller-home',
                'PATH' => '/tmp/caller-bin',
            ],
        ],
        'restart_policy' => 'never',
    ]);
    $process->id = 8;

    $plist = new LaunchdProcessRenderer()->render(
        $process,
        new ProcessTarget(new Node(['platform' => 'darwin']), 'nckrtl', '/Users/nckrtl/apps/docs'),
    );

    expect($plist)
        ->toContain('<key>HOME</key>', '<string>/Users/nckrtl</string>')
        ->toContain(
            '<key>PATH</key>',
            '<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>',
        )
        ->not->toContain('/tmp/caller-home')
        ->not->toContain('/tmp/caller-bin');
});

it('keeps persisted environment values out of renderer helper traces', function (string $method): void {
    $sentinel = 'launchd-renderer-trace-sentinel';
    $process = new Process([
        'name' => 'INVALID',
        'runtime' => ProcessRuntime::Launchd,
        'working_directory' => '/Users/nckrtl/apps/docs',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan'],
            'environment' => ['TRACE_VALUE' => $sentinel],
        ],
        'restart_policy' => 'never',
    ]);
    $process->id = 9;
    $target = new ProcessTarget(
        new Node(['platform' => 'darwin']),
        'nckrtl',
        '/Users/nckrtl/apps/docs',
    );
    $renderer = new LaunchdProcessRenderer;

    try {
        match ($method) {
            'label' => $renderer->label($process),
            'plistPath' => $renderer->plistPath($process, $target),
            'stdoutPath' => $renderer->stdoutPath($process, $target),
            'stderrPath' => $renderer->stderrPath($process, $target),
            'render' => $renderer->render($process, $target),
        };
    } catch (InvalidArgumentException $exception) {
        expect(json_encode($exception->getTrace(), JSON_THROW_ON_ERROR))->not->toContain($sentinel);

        return;
    }

    $this->fail("Expected renderer helper [{$method}] to reject the invalid process name.");
})->with(['label', 'plistPath', 'stdoutPath', 'stderrPath', 'render']);

it('marks every renderer process helper parameter sensitive', function (string $method): void {
    $parameter = new ReflectionMethod(LaunchdProcessRenderer::class, $method)->getParameters()[0];

    expect($parameter->getAttributes(SensitiveParameter::class))->toHaveCount(1);
})->with(['label', 'plistPath', 'stdoutPath', 'stderrPath', 'render']);
