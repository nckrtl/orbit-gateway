<?php

declare(strict_types=1);

use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Ssh\RemoteCommand;

it('passes a sudo-free user-owned command through unchanged', function (): void {
    $command = new RemoteCommand([
        '/opt/homebrew/opt/caddy/bin/caddy',
        'validate',
        '--config',
        '/Users/nckrtl/.orbit/caddy/Caddyfile',
    ]);

    $guarded = new MacOsSteadyStateCommandGuard()->guard($command);

    expect($guarded)->toBe($command);
});

it('rejects sudo and protected targets from every steady-state command surface', function (
    RemoteCommand $command,
): void {
    expect(fn (): RemoteCommand => new MacOsSteadyStateCommandGuard()->guard($command))
        ->toThrow(UnexpectedValueException::class, 'Darwin steady-state commands cannot use sudo or protected paths.');
})->with([
    'sudo executable' => [new RemoteCommand(['/usr/bin/sudo', '/bin/true'])],
    'sudo shell token' => [new RemoteCommand(['/bin/bash', '-c', 'sudo true'])],
    'PF anchor' => [new RemoteCommand(['/bin/cp', '/tmp/candidate', '/etc/pf.anchors/com.orbit.app-dev'])],
    'PF configuration' => [new RemoteCommand(['/usr/bin/sed', '-i', '', '/etc/pf.conf'])],
    'dnsmasq configuration' => [new RemoteCommand([
        '/bin/cat',
        '/Library/Application Support/Orbit/app-dev/dnsmasq.conf',
    ])],
    'dnsmasq daemon' => [new RemoteCommand(['/bin/launchctl', 'kickstart', 'system/com.orbit.dnsmasq'])],
    'resolver' => [new RemoteCommand(['/bin/cat'], input: '/etc/resolver/test')],
    'Remote Login' => [new RemoteCommand(['/usr/sbin/systemsetup', '-setremotelogin', 'on'])],
]);
