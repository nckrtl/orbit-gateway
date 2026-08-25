<?php

declare(strict_types=1);

use App\Domain\Certificates\GatewayCertificateIssuer;
use App\Domain\Certificates\GatewayCertificatePaths;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Gateway\GatewayCaddyConfigRenderer;
use App\Infrastructure\Gateway\GatewayCheckoutAccessConverger;
use App\Infrastructure\Gateway\GatewayFpmConfigRenderer;
use App\Infrastructure\Gateway\NativeGatewayCaddyConverger;
use App\Infrastructure\Gateway\NativeGatewayCertificatePublisher;
use App\Infrastructure\Gateway\NativeGatewayFpmConverger;
use App\Infrastructure\Gateway\NativeGatewayWebConverger;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/** @mago-expect lint:halstead The interaction test keeps each security-sensitive publication boundary observable. */
it('publishes complete validated FPM Caddy and certificate configurations through atomic switches', function (): void {
    [$converger, $processes, $issuer, $orbitHome] = gateway_web_converger();

    try {
        $converger->converge('gateway.orbit', '10.44.0.1');
        $calls = Collection::make($processes->calls);
        $commands = $calls->map(static fn (ProcessInvocation $invocation): array => $invocation->arguments);
        $fpmValidationIndex = $commands->search(
            static fn (array $arguments): bool => $arguments === [
                'sudo',
                'php-fpm8.5',
                '--test',
                '--fpm-config',
                '/etc/php/8.5/fpm/orbit-gateway-candidate.conf',
            ],
        );
        $fpmPublishIndex = $commands->search(
            static fn (array $arguments): bool => $arguments === [
                'sudo',
                'mv',
                '-f',
                '--',
                '/etc/php/8.5/fpm/orbit-candidate.d/orbit-gateway.conf',
                '/etc/php/8.5/fpm/pool.d/orbit-gateway.conf',
            ],
        );
        $caddyValidationIndex = $commands->search(
            static fn (array $arguments): bool => (
                $arguments[0] === 'sudo'
                && $arguments[1] === 'caddy'
                && $arguments[2] === 'validate'
                && str_ends_with($arguments[4] ?? '', '/Caddyfile')
                && str_contains($arguments[4], '/etc/caddy/orbit-versions/')
            ),
        );
        $caddyPublishIndex = $commands->search(
            static fn (array $arguments): bool => (
                array_slice(array: $arguments, offset: 0, length: 4) === ['sudo', 'mv', '-Tf', '--']
                && end($arguments) === '/etc/caddy/Caddyfile'
            ),
        );
        $certificatePublish = $commands->first(
            static fn (array $arguments): bool => (
                array_slice(array: $arguments, offset: 0, length: 4) === ['sudo', 'mv', '-Tf', '--']
                && end($arguments) === '/etc/caddy/orbit-cert-current'
            ),
        );
        $fpmStage = $calls->first(
            static fn (ProcessInvocation $invocation): bool => (
                $invocation->arguments[0] === 'sudo'
                && $invocation->arguments[1] === 'bash'
                && str_contains($invocation->input ?? '', 'orbit-candidate.d')
            ),
        );
        $caddyStage = $calls->first(
            static fn (ProcessInvocation $invocation): bool => (
                $invocation->arguments[0] === 'sudo'
                && $invocation->arguments[1] === 'bash'
                && str_contains($invocation->input ?? '', 'orbit-versions')
            ),
        );

        expect($issuer->calls)
            ->toBe([['hostname' => 'gateway.orbit', 'address' => '10.44.0.1']])
            ->and(file_get_contents($orbitHome.'/generated/gateway/php-fpm-pool.conf'))
            ->toContain(
                '[orbit-gateway]',
                'listen = /run/php/orbit-gateway.sock',
                'listen.group = caddy',
                'listen.mode = 0660',
                'php_admin_value[opcache.validate_timestamps] = 1',
            )
            ->and(file_get_contents($orbitHome.'/generated/gateway/Caddyfile'))
            ->toContain(
                'gateway.orbit, 10.44.0.1',
                'bind 10.44.0.1',
                'root * /home/orbit/orbit-gateway/public',
                'tls /etc/caddy/orbit-cert-current/gateway.pem /etc/caddy/orbit-cert-current/gateway.key',
                'php_fastcgi unix//run/php/orbit-gateway.sock',
            )
            ->and($fpmStage?->input)
            ->toContain(
                'for pool in /etc/php/8.5/fpm/pool.d/*.conf',
                'if [ "$pool_name" = orbit-gateway.conf ]; then',
                'cp --preserve=mode,ownership -- "$pool" "$candidate_directory/$pool_name"',
                'replacement_count',
            )
            ->and($fpmValidationIndex)
            ->toBeInt()
            ->toBeLessThan($fpmPublishIndex)
            ->and($caddyStage?->input)
            ->toContain(
                'source_main=$(readlink -f /etc/caddy/Caddyfile)',
                'previous_fragments=$(dirname "$source_main")/fragments',
                'orbit-versions',
            )
            ->and($caddyValidationIndex)
            ->toBeInt()
            ->toBeLessThan($caddyPublishIndex)
            ->and($certificatePublish)
            ->toBeArray()
            ->and($commands->contains(
                static fn (array $arguments): bool => (
                    in_array(needle: '/etc/caddy/orbit-cert-current/gateway.pem', haystack: $arguments, strict: true)
                    || in_array(needle: '/etc/caddy/orbit-cert-current/gateway.key', haystack: $arguments, strict: true)
                ),
            ))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'chmod', '0710', '/home/orbit', '/home/orbit/orbit-gateway']))
            ->toBeTrue()
            ->and($commands->contains(['sudo', 'chmod', '0600', '/home/orbit/orbit-gateway/.env']))
            ->toBeTrue();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('adapts Caddy to a listener bound only to the gateway WireGuard address', function (): void {
    $configuration = new GatewayCaddyConfigRenderer()->render(
        hostname: 'gateway.orbit',
        wireguardAddress: '10.44.0.1',
        checkoutPath: '/home/orbit/orbit-gateway',
    );
    $result = new NativeProcessRunner()->run(new ProcessInvocation(
        arguments: ['caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile'],
        input: $configuration,
    ));
    /** @var array{apps: array{http: array{servers: array<string, array{listen: list<string>}>}}} $adapted */
    $adapted = json_decode(json: $result->stdout, associative: true, flags: JSON_THROW_ON_ERROR);
    $listeners = Collection::make($adapted['apps']['http']['servers'])
        ->flatMap(static fn (array $server): array => $server['listen'])
        ->values()
        ->all();

    expect($result->succeeded())
        ->toBeTrue()
        ->and($listeners)
        ->toBe(['10.44.0.1:443'])
        ->not->toContain(':443', '0.0.0.0:443');
});

it('preserves live FPM disk and does not reload when complete effective validation fails', function (): void {
    [$converger, $processes, , $orbitHome] = gateway_web_converger(failure: 'fpm-validation');

    try {
        expect(fn () => $converger->converge('gateway.orbit', '10.44.0.1'))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('gateway-fpm-validate')
                    ->and($exception->errorCode)
                    ->toBe('gateway.fpm_config_invalid');
            });

        $commands = Collection::make($processes->calls)
            ->map(static fn (ProcessInvocation $invocation): array => $invocation->arguments);

        expect($commands->contains([
            'sudo',
            'mv',
            '-f',
            '--',
            '/etc/php/8.5/fpm/orbit-candidate.d/orbit-gateway.conf',
            '/etc/php/8.5/fpm/pool.d/orbit-gateway.conf',
        ]))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'systemctl', 'reload-or-restart', 'php8.5-fpm']))
            ->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('preserves the prior aggregate Caddy configuration when staged final validation fails', function (): void {
    [$converger, $processes, , $orbitHome] = gateway_web_converger(failure: 'caddy-validation');

    try {
        expect(fn () => $converger->converge('gateway.orbit', '10.44.0.1'))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('gateway-caddy-validate')
                    ->and($exception->errorCode)
                    ->toBe('gateway.caddy_config_invalid');
            });

        $commands = Collection::make($processes->calls)
            ->map(static fn (ProcessInvocation $invocation): array => $invocation->arguments);

        expect($commands->contains(
            static fn (array $arguments): bool => (
                array_slice(array: $arguments, offset: 0, length: 4) === ['sudo', 'mv', '-Tf', '--']
                && end($arguments) === '/etc/caddy/Caddyfile'
            ),
        ))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'systemctl', 'reload-or-restart', 'caddy']))
            ->toBeFalse()
            ->and($commands->contains(
                static fn (array $arguments): bool => $arguments[0] === 'sudo'
                && $arguments[1] === 'rm'
                && in_array(needle: '/etc/caddy/Caddyfile', haystack: $arguments, strict: true),
            ))
            ->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('does not disturb the published Caddy certificate pair when its atomic link switch fails', function (): void {
    [$converger, $processes, , $orbitHome] = gateway_web_converger(failure: 'certificate-publication');

    try {
        expect(fn () => $converger->converge('gateway.orbit', '10.44.0.1'))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('gateway-certificate-publish')
                    ->and($exception->errorCode)
                    ->toBe('gateway.certificate_publish_failed');
            });

        $commands = Collection::make($processes->calls)
            ->map(static fn (ProcessInvocation $invocation): array => $invocation->arguments);

        expect($commands->contains(
            static fn (array $arguments): bool => $arguments[0] === 'sudo'
            && $arguments[1] === 'rm'
            && in_array(needle: '/etc/caddy/orbit-cert-current', haystack: $arguments, strict: true),
        ))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'systemctl', 'reload-or-restart', 'php8.5-fpm']))
            ->toBeFalse()
            ->and($commands->contains(['sudo', 'systemctl', 'reload-or-restart', 'caddy']))
            ->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('rejects a checkout outside the configured Orbit home before certificate or sudo work', function (): void {
    [$converger, $processes, $issuer, $orbitHome] = gateway_web_converger(
        checkoutPath: '/home/nckrtl/orbit/gateway',
    );

    try {
        expect(fn () => $converger->converge('gateway.orbit', '10.44.0.1'))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('gateway-checkout-validate')
                    ->and($exception->errorCode)
                    ->toBe('gateway.checkout_invalid');
            })
            ->and($issuer->calls)
            ->toBeEmpty()
            ->and($processes->calls)
            ->toBeEmpty();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

/**
 * @return array{
 *     NativeGatewayWebConverger,
 *     object&ProcessRunner,
 *     object&GatewayCertificateIssuer,
 *     string
 * }
 */
function gateway_web_converger(?string $failure = null, string $checkoutPath = '/home/orbit/orbit-gateway'): array
{
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-web-'.Str::uuid();
    mkdir(directory: $orbitHome.'/ca/gateway-current', permissions: 0o700, recursive: true);
    file_put_contents(filename: $orbitHome.'/ca/gateway-current/gateway.key', data: 'PRIVATE KEY');
    file_put_contents(filename: $orbitHome.'/ca/gateway-current/gateway.pem', data: 'CERTIFICATE');
    $issuer = new class($orbitHome) implements GatewayCertificateIssuer {
        /** @var list<array{hostname: string, address: string}> */
        public array $calls = [];

        public function __construct(
            private readonly string $orbitHome,
        ) {}

        public function issue(string $hostname, string $wireguardAddress): GatewayCertificatePaths
        {
            $this->calls[] = ['hostname' => $hostname, 'address' => $wireguardAddress];

            return new GatewayCertificatePaths(
                privateKeyPath: $this->orbitHome.'/ca/gateway-current/gateway.key',
                certificatePath: $this->orbitHome.'/ca/gateway-current/gateway.pem',
            );
        }
    };
    $processes = new class($failure) implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $calls = [];

        public function __construct(
            private readonly ?string $failure,
        ) {}

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->calls[] = $invocation;
            $arguments = $invocation->arguments;

            if (
                $this->failure === 'fpm-validation'
                && $arguments === [
                    'sudo',
                    'php-fpm8.5',
                    '--test',
                    '--fpm-config',
                    '/etc/php/8.5/fpm/orbit-gateway-candidate.conf',
                ]
            ) {
                return new CommandResult(1, '', 'duplicate pool listener', 2, false);
            }

            if (
                $this->failure === 'caddy-validation'
                && $arguments[1] === 'caddy'
                && $arguments[2] === 'validate'
                && str_contains($arguments[4] ?? '', '/etc/caddy/orbit-versions/')
            ) {
                return new CommandResult(1, '', 'aggregate route conflict', 2, false);
            }

            if (
                $this->failure === 'certificate-publication'
                && array_slice(array: $arguments, offset: 0, length: 4) === ['sudo', 'mv', '-Tf', '--']
                && end($arguments) === '/etc/caddy/orbit-cert-current'
            ) {
                return new CommandResult(1, '', 'atomic link switch failed', 2, false);
            }

            if ($arguments[1] === 'openssl' && in_array(needle: '-pubout', haystack: $arguments, strict: true)) {
                return new CommandResult(0, "PUBLIC KEY\n", '', 2, false);
            }

            if ($arguments[1] === 'openssl' && in_array(needle: '-pubkey', haystack: $arguments, strict: true)) {
                return new CommandResult(0, "PUBLIC KEY\n", '', 2, false);
            }

            return new CommandResult(0, '', '', 2, false);
        }
    };

    return [
        new NativeGatewayWebConverger(
            certificates: $issuer,
            caddyRenderer: new GatewayCaddyConfigRenderer,
            fpmRenderer: new GatewayFpmConfigRenderer,
            files: new ProtectedFileWriter,
            checkout: new GatewayCheckoutAccessConverger($processes, $checkoutPath),
            certificatePublisher: new NativeGatewayCertificatePublisher($processes, $orbitHome),
            fpm: new NativeGatewayFpmConverger($processes),
            caddy: new NativeGatewayCaddyConverger($processes),
            orbitHome: $orbitHome,
            checkoutPath: $checkoutPath,
        ),
        $processes,
        $issuer,
        $orbitHome,
    ];
}
