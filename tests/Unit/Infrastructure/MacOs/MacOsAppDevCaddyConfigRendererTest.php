<?php

declare(strict_types=1);

use App\Infrastructure\AppDev\AppDevSite;
use App\Infrastructure\MacOs\MacOsAppDevCaddyConfigRenderer;
use App\Infrastructure\MacOs\MacOsFilesystemLayout;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;

it('renders only the WireGuard HTTP and HTTPS listeners with the admin and HTTP 3 disabled', function (): void {
    $site = new AppDevSite(
        nodeId: 9,
        nodeAddress: '10.44.0.9',
        scope: 'instance-3',
        checkoutPath: '/Users/nckrtl/apps/acme',
        documentRoot: 'public',
        phpVersion: '8.5',
        hostname: 'acme.mini.orbit',
        platform: 'darwin',
        home: '/Users/nckrtl',
    );
    $configuration = new MacOsAppDevCaddyConfigRenderer(new MacOsFilesystemLayout)->render(collect([$site]));
    $adapted = new NativeProcessRunner()->run(new ProcessInvocation(
        arguments: ['caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile'],
        input: $configuration,
    ));

    expect($configuration)
        ->toStartWith("{\n    admin off\n    http_port 8080\n    https_port 8443")
        ->toContain(
            'default_bind 10.44.0.9',
            'servers 10.44.0.9:8443',
            'protocols h1 h2',
            'http://acme.mini.orbit:8080',
            'redir https://{host}{uri} permanent',
            'https://acme.mini.orbit:8443',
            'bind 10.44.0.9',
            'tls /Users/nckrtl/.orbit/certificates/instance-3/current/cert.pem /Users/nckrtl/.orbit/certificates/instance-3/current/key.pem',
            'php_fastcgi unix//Users/nckrtl/.orbit/run/php/orbit-instance-3.sock',
        )
        ->not->toContain('0.0.0.0')
        ->not->toContain('127.0.0.1')
        ->not->toContain('localhost')
        ->not->toContain(':2019')
        ->not->toContain('h3')
        ->not->toContain('udp')->and(
            $adapted->succeeded(),
        )->toBeTrue($adapted->stderr)->and($adapted->stdout)->toContain('10.44.0.9:8080', '10.44.0.9:8443')
        ->not->toContain('0.0.0.0')
        ->not->toContain('127.0.0.1')
        ->not->toContain(':2019')
        ->not->toContain('"protocols":["h1","h2","h3"]');
});
