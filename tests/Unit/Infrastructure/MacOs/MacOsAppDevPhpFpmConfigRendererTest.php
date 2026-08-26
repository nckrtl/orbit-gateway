<?php

declare(strict_types=1);

use App\Infrastructure\AppDev\AppDevSite;
use App\Infrastructure\MacOs\MacOsAppDevPhpFpmConfigRenderer;
use App\Infrastructure\MacOs\MacOsFilesystemLayout;

it('renders one user master with a health pool and one isolated pool per scope', function (): void {
    $sites = collect([
        new AppDevSite(
            nodeId: 9,
            nodeAddress: '10.44.0.9',
            scope: 'instance-3',
            checkoutPath: '/Users/nckrtl/apps/acme',
            documentRoot: 'public',
            phpVersion: '8.5',
            hostname: 'acme.mini.orbit',
            platform: 'darwin',
            home: '/Users/nckrtl',
        ),
    ]);

    $configuration = new MacOsAppDevPhpFpmConfigRenderer(new MacOsFilesystemLayout)->render(
        version: '8.5',
        sites: $sites,
        home: '/Users/nckrtl',
        user: 'nckrtl',
        brewPrefix: '/opt/homebrew',
    );

    expect($configuration)
        ->toContain(
            '[global]',
            'daemonize = no',
            'error_log = /Users/nckrtl/.orbit/logs/php-fpm-8.5.log',
            '[orbit-health]',
            'listen = /Users/nckrtl/.orbit/run/php/health-8.5.sock',
            '[orbit-instance-3]',
            'listen = /Users/nckrtl/.orbit/run/php/orbit-instance-3.sock',
            'chdir = /Users/nckrtl/apps/acme',
            'env[HOME] = /Users/nckrtl',
            'env[USER] = nckrtl',
            'env[PATH] = /opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin',
            'request_slowlog_timeout = 5s',
            'request_terminate_timeout = 120s',
        )
        ->not->toContain('user =')
        ->not->toContain('group =')
        ->not->toContain('listen.owner')
        ->not->toContain('listen.group')
        ->not->toContain('opcache');
});
