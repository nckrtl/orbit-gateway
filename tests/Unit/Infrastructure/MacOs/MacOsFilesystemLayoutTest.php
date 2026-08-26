<?php

declare(strict_types=1);

use App\Infrastructure\MacOs\MacOsFilesystemLayout;

it('derives only user-owned runtime configuration and log paths', function (): void {
    $layout = new MacOsFilesystemLayout;
    $home = '/Users/nckrtl';

    expect($layout->caddyRoot($home))
        ->toBe('/Users/nckrtl/.orbit/caddy')
        ->and($layout->caddyCurrent($home))
        ->toBe('/Users/nckrtl/.orbit/caddy/Caddyfile')
        ->and($layout->caddyLock($home))
        ->toBe('/Users/nckrtl/.orbit/run/caddy.lock')
        ->and($layout->caddyLog($home))
        ->toBe('/Users/nckrtl/.orbit/logs/caddy.log')
        ->and($layout->phpCurrent($home, '8.5'))
        ->toBe('/Users/nckrtl/.orbit/php/8.5/php-fpm.conf')
        ->and($layout->phpLock($home, '8.5'))
        ->toBe('/Users/nckrtl/.orbit/run/php/php-fpm-8.5.lock')
        ->and($layout->phpSocket($home, 'instance-3'))
        ->toBe('/Users/nckrtl/.orbit/run/php/orbit-instance-3.sock')
        ->and($layout->phpHealthSocket($home, '8.5'))
        ->toBe('/Users/nckrtl/.orbit/run/php/health-8.5.sock')
        ->and($layout->phpLog($home, '8.5'))
        ->toBe('/Users/nckrtl/.orbit/logs/php-fpm-8.5.log')
        ->and($layout->certificateCurrent($home, 'workspace-4'))
        ->toBe('/Users/nckrtl/.orbit/certificates/workspace-4/current')
        ->and($layout->launchAgent($home, 'com.orbit.caddy'))
        ->toBe('/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist');
});
