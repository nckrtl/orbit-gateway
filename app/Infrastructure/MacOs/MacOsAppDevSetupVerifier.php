<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\MacOs\MacOsAppDevVerifier as MacOsAppDevVerifierContract;
use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use Closure;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity Verification keeps ordered transport and named live checks together.
 * @mago-expect lint:excessive-parameter-list The verifier composes five explicit SSH safety boundaries.
 * @mago-expect lint:kan-defect The score reflects independent fail-closed verification checks.
 * @mago-expect lint:too-many-methods Narrow methods keep each stable verification check explicit.
 */
final readonly class MacOsAppDevSetupVerifier implements MacOsAppDevVerifierContract
{
    public function __construct(
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private SshKeyProvider $sshKeys,
        private MacOsSteadyStateCommandGuard $guard,
        private MacOsProtectedStateInspector $protectedState,
        /** @var (Closure(): string)|null */
        private ?Closure $gatewayAddressResolver = null,
    ) {}

    public function verify(Node $node): void
    {
        $connection = $this->connections->make($node);
        $identity = $this->execute($connection, new RemoteCommand(['/usr/bin/id', '-un']));

        if (! $identity->succeeded()) {
            throw $this->unreachable();
        }

        if (trim($identity->stdout) !== $node->ssh_user) {
            throw $this->verificationFailure('identity');
        }

        $userId = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/usr/bin/id', '-u']),
            'identity',
        );
        $userIdValue = trim($userId->stdout);

        if (preg_match('/\A[1-9][0-9]*\z/D', $userIdValue) !== 1) {
            throw $this->verificationFailure('identity');
        }

        $architecture = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/usr/bin/uname', '-m']),
            'architecture',
        );

        if (trim($architecture->stdout) !== $node->architecture) {
            throw $this->verificationFailure('architecture');
        }

        $guiDomain = $this->execute(
            $connection,
            new RemoteCommand(['/bin/launchctl', 'print', "gui/{$userIdValue}"]),
        );

        if (! $guiDomain->succeeded()) {
            throw new ResourceOperationException(
                errorCode: 'macos.user_session_unavailable',
                message: 'The macOS launchd GUI domain is unavailable.',
                status: 409,
                safeDetails: ['runtime' => 'launchd'],
            );
        }

        try {
            $this->protectedState->inspect($node, $connection);
        } catch (MacOsProtectedDriftException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw $this->unreachable();
        }

        $this->verifyRestrictedKey($node, $connection);
        $brewPrefix = $this->verifyHomebrew($node, $connection);
        $this->verifyToolchain($connection, $brewPrefix);
        $this->verifyCaddy($node, $connection, $userIdValue, $brewPrefix);
        $this->verifyPhpFpm($node, $connection, $userIdValue);
    }

    private function verifyRestrictedKey(Node $node, SshConnection $connection): void
    {
        $authorizedKeys = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/bin/cat', "/Users/{$node->ssh_user}/.ssh/authorized_keys"]),
            'restricted-key',
        );
        $expected =
            'from="'
            .$this->gatewayAddress()
            .'",no-agent-forwarding,no-port-forwarding,'
            .'no-X11-forwarding,no-pty,no-user-rc '
            .$this->sshKeys->publicKey();
        $lines = preg_split('/\R/', trim($authorizedKeys->stdout));
        $lines = is_array($lines) ? $lines : [];

        if (count(array_keys($lines, $expected, true)) !== 1) {
            throw $this->verificationFailure('restricted-key');
        }

        $sshDirectory = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/usr/bin/stat', '-f', '%Su:%Lp', "/Users/{$node->ssh_user}/.ssh"]),
            'restricted-key',
        );
        $authorizedKeysFile = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/usr/bin/stat', '-f', '%Su:%Lp', "/Users/{$node->ssh_user}/.ssh/authorized_keys"]),
            'restricted-key',
        );

        if (
            trim($sshDirectory->stdout) !== "{$node->ssh_user}:700"
            || trim($authorizedKeysFile->stdout) !== "{$node->ssh_user}:600"
        ) {
            throw $this->verificationFailure('restricted-key');
        }
    }

    private function verifyHomebrew(Node $node, SshConnection $connection): string
    {
        $brewPrefix = match ($node->architecture) {
            'arm64' => '/opt/homebrew',
            'x86_64' => '/usr/local',
            default => throw $this->verificationFailure('architecture'),
        };
        $result = $this->requireSuccessful(
            $connection,
            new RemoteCommand(["{$brewPrefix}/bin/brew", '--prefix']),
            'homebrew',
        );

        if (trim($result->stdout) !== $brewPrefix) {
            throw $this->verificationFailure('homebrew');
        }

        return $brewPrefix;
    }

    private function verifyToolchain(SshConnection $connection, string $brewPrefix): void
    {
        $commands = [
            ["{$brewPrefix}/opt/caddy/bin/caddy",       'version'],
            ["{$brewPrefix}/opt/dnsmasq/sbin/dnsmasq",  '--version'],
            ["{$brewPrefix}/opt/php/bin/php",           '--version'],
            ["{$brewPrefix}/bin/composer",              '--version'],
            ["{$brewPrefix}/bin/git",                   '--version'],
            ["{$brewPrefix}/opt/openssl@3/bin/openssl", 'version'],
        ];

        foreach ($commands as $arguments) {
            $result = $this->requireSuccessful($connection, new RemoteCommand($arguments), 'toolchain');

            if (trim($result->stdout.$result->stderr) === '') {
                throw $this->verificationFailure('toolchain');
            }
        }

        $ed25519 = $this->requireSuccessful(
            $connection,
            new RemoteCommand(["{$brewPrefix}/opt/openssl@3/bin/openssl", 'list', '-public-key-algorithms']),
            'toolchain',
        );

        if (! str_contains(strtoupper($ed25519->stdout), 'ED25519')) {
            throw $this->verificationFailure('toolchain');
        }
    }

    private function verifyCaddy(
        Node $node,
        SshConnection $connection,
        string $userId,
        string $brewPrefix,
    ): void {
        $home = "/Users/{$node->ssh_user}";
        $config = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/bin/cat', "{$home}/.orbit/caddy/Caddyfile"]),
            'caddy',
        );

        if (
            ! str_contains($config->stdout, 'admin off')
            || str_contains($config->stdout, ':2019')
            || str_contains($config->stdout, 'localhost')
            || str_contains($config->stdout, '127.0.0.1')
        ) {
            throw $this->verificationFailure('caddy');
        }

        $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/bin/launchctl', 'print', "gui/{$userId}/com.orbit.caddy"]),
            'caddy',
        );
        $listeners = $this->requireSuccessful(
            $connection,
            new RemoteCommand(['/usr/sbin/lsof', '-nP', '-a', '-c', 'caddy', '-iTCP', '-sTCP:LISTEN', '-Fn']),
            'caddy',
        );
        $address = (string) $node->wireguard_address;
        $listenerLines = preg_split('/\R/', trim($listeners->stdout));
        $listenerLines = is_array($listenerLines)
            ? array_values(array_filter($listenerLines, static fn (string $line): bool => str_starts_with($line, 'n')))
            : [];
        $hasHttp = false;
        $hasHttps = false;

        foreach ($listenerLines as $line) {
            if (
                str_contains($line, '127.0.0.1')
                || str_contains($line, 'localhost')
                || str_contains($line, '*:')
                || str_contains($line, ':2019')
            ) {
                throw $this->verificationFailure('caddy');
            }

            if ($line === "n{$address}:8080") {
                $hasHttp = true;

                continue;
            }

            if ($line === "n{$address}:8443") {
                $hasHttps = true;

                continue;
            }

            throw $this->verificationFailure('caddy');
        }

        if (! $hasHttp || ! $hasHttps) {
            throw $this->verificationFailure('caddy');
        }

        $this->requireSuccessful(
            $connection,
            new RemoteCommand([
                "{$brewPrefix}/opt/caddy/bin/caddy",
                'validate',
                '--config',
                "{$home}/.orbit/caddy/Caddyfile",
                '--adapter',
                'caddyfile',
            ]),
            'caddy',
        );
    }

    private function verifyPhpFpm(Node $node, SshConnection $connection, string $userId): void
    {
        $home = "/Users/{$node->ssh_user}";
        $definitions = $this->requireSuccessful(
            $connection,
            new RemoteCommand([
                '/usr/bin/find',
                "{$home}/Library/LaunchAgents",
                '-type',
                'f',
                '-name',
                'com.orbit.php-fpm.*.plist',
            ]),
            'php-fpm',
        );
        $paths = preg_split('/\R/', trim($definitions->stdout));
        $paths = is_array($paths) ? array_values(array_filter($paths)) : [];

        if ($paths === []) {
            throw $this->verificationFailure('php-fpm');
        }

        foreach ($paths as $path) {
            $matches = [];

            if (
                preg_match(
                    '/\A'
                    .preg_quote(str: "{$home}/Library/LaunchAgents/", delimiter: '/')
                    .'com\.orbit\.php-fpm\.([0-9]+\.[0-9]+)\.plist\z/D',
                    $path,
                    $matches,
                ) !== 1
            ) {
                throw $this->verificationFailure('php-fpm');
            }

            $version = $matches[1];
            $this->requireSuccessful(
                $connection,
                new RemoteCommand(['/bin/launchctl', 'print', "gui/{$userId}/com.orbit.php-fpm.{$version}"]),
                'php-fpm',
            );
            $this->requireSuccessful(
                $connection,
                new RemoteCommand(['/bin/test', '-S', "{$home}/.orbit/run/php/health-{$version}.sock"]),
                'php-fpm',
            );
        }
    }

    private function requireSuccessful(
        SshConnection $connection,
        RemoteCommand $command,
        string $check,
    ): CommandResult {
        $result = $this->execute($connection, $command);

        if (! $result->succeeded()) {
            throw $this->verificationFailure($check);
        }

        return $result;
    }

    private function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        try {
            return $this->ssh->execute($connection, $this->guard->guard($command));
        } catch (ResourceOperationException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw $this->unreachable();
        }
    }

    private function verificationFailure(string $check): ResourceOperationException
    {
        return new ResourceOperationException(
            errorCode: 'macos.verification_failed',
            message: "The live macOS verification check [{$check}] failed.",
            status: 502,
            safeDetails: ['check' => $check],
        );
    }

    private function unreachable(): ResourceOperationException
    {
        return new ResourceOperationException(
            errorCode: 'node.unreachable',
            message: 'The macOS node is not reachable over WireGuard SSH.',
            status: 502,
        );
    }

    private function gatewayAddress(): string
    {
        if ($this->gatewayAddressResolver instanceof Closure) {
            $address = ($this->gatewayAddressResolver)();

            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                throw $this->verificationFailure('restricted-key');
            }

            return $address;
        }

        $gateways = Node::query()
            ->whereHas('roles', static fn ($query) => $query->where('role', RoleName::Gateway->value))
            ->get();

        if ($gateways->count() !== 1) {
            throw $this->verificationFailure('restricted-key');
        }

        $address = $gateways->sole()->wireguard_address;

        if (! is_string($address) || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw $this->verificationFailure('restricted-key');
        }

        return $address;
    }
}
